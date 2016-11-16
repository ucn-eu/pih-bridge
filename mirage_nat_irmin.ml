open Lwt
open Result
open Mirage_nat

let src = Logs.Src.create "nat-irmin-tbl" ~doc:"Mirage NAT with Irmin Http backend"
module Log = (val Logs.src_log src : Logs.LOG)

let string_of_protocol = function
  | Tcp -> "tcp"
  | Udp -> "udp"

let string_of_endpoint (ip, port) =
  Printf.sprintf "%s:%d" (Ipaddr.to_string ip) port

let endpoint_of_string str =
  match Astring.String.cut ~sep:":" str with
  | None -> failwith (Printf.sprintf "endpoint_of_string %s" str)
  | Some (ip, port) ->
     try (Ipaddr.of_string_exn ip, int_of_string port)
     with Failure fl -> Log.err (fun f -> f "endpoint_of_string %s: %s" fl str);
                       failwith "wtf"

let string_of_mapping (src, dst) =
  Printf.sprintf "%s_%s" (string_of_endpoint src) (string_of_endpoint dst)

let mapping_of_string str =
  match Astring.String.cut ~sep:"_" str with
  | None -> failwith (Printf.sprintf "endpoint_of_string %s" str)
  | Some (endpx, endpy) -> (endpoint_of_string endpx, endpoint_of_string endpy)


let to_entry lookup mapping =
  List.map string_of_mapping [lookup; mapping]


type storage_config = {
    resolver : Resolver_lwt.t;
    conduit  : Conduit_mirage.t;
    uri      : Uri.t;
    owner    : string;
    now      : unit -> int64;
  }

module type STORAGE = sig
    include Mirage_nat.Lookup with type config = storage_config

    val add_source_port: t -> mapping -> unit Lwt.t
    val list_source_ports: t -> Ipaddr.t * endpoint -> port list Lwt.t
    val remove_source_ports: t -> Ipaddr.t * endpoint -> unit Lwt.t

    val add_entry: t -> (Ipaddr.t * endpoint) * endpoint -> unit Lwt.t
    val read_entry: t -> Ipaddr.t * endpoint -> endpoint option Lwt.t
    val remove_entry: t -> Ipaddr.t * endpoint -> unit Lwt.t
end

module Storage : STORAGE = struct

  module S = Data_store

  type t = S.t * (unit -> int64) * S.key Queue.t

  type config = storage_config

  let empty {resolver; conduit; uri; owner; now} =
    let time = fun () -> now () |> Int64.to_string in
    let backend = `Http ((resolver, conduit, uri), owner) in
    S.make ~backend ~time () >>= fun s -> return (s, now, Queue.create ())

  let store_of_t (t, _, _) = t

  let insert (s, n, q) timeout prot trans =
    let root = string_of_protocol prot in
    let expiration = Int64.(add (n ()) timeout |> to_string) in

    let outbnd_dir = root :: ["outbound"] in
    let outbnd_path = to_entry trans.internal_lookup trans.internal_mapping in
    let outbnd_path = outbnd_dir @ outbnd_path in

    let inbnd_dir = root :: ["inbound"] in
    let inbnd_path = to_entry trans.external_lookup trans.external_mapping in
    let inbnd_path = inbnd_dir @ inbnd_path in

    S.create s inbnd_path expiration >>= (function
    | Error exn ->
       let err = Printexc.to_string exn in
       Log.err (fun f -> f "insert %s failed: %s" (String.concat "/" inbnd_path) err);
       return_none
    | Ok () ->
       S.create s outbnd_path expiration >>= (function
       | Error exn ->
          let err = Printexc.to_string exn in
          Log.err (fun f -> f "insert %s failed: %s" (String.concat "/" outbnd_path) err);
          S.remove s inbnd_path |> Lwt.ignore_result;
          return_none
       | Ok () ->
          Queue.push inbnd_path q;
          Queue.push outbnd_path q;
          return_some (s, n, q)))


  let sanitize (s, n, q) =
    let rec aux () =
      let path = Queue.peek q in
      S.read s path >>= function
      | Error exn ->
         let err = Printexc.to_string exn in
         Log.err (fun f -> f "read %s failed: %s" (String.concat "/" path) err);
         aux ()
      | Ok t ->
         let now = n () in
         let expiration = Int64.of_string t in
         if Int64.compare expiration now < 0 then begin
             Log.debug (fun f -> f "expiration removal: %s" (String.concat "/" path));
             S.remove s path >>= function
             | Error _ -> return_unit
             | Ok () -> aux () end
         else return_unit in
    aux ()


  let lookup (s, n, q) prot ~source ~destination =
    let root = string_of_protocol prot in
    let subdir = string_of_mapping (source, destination) in
    let paths = List.map (fun direction -> root :: direction :: [subdir]) ["inbound"; "outbound"] in
    Lwt_list.fold_left_s (fun acc path ->
      if acc <> None then return acc
      else
        S.list s ~parent:path () >>= function
        | Error exn -> return_none
        | Ok mappings ->
           let cnt = List.length mappings in
           if cnt = 0 then return_none
           else
             let path = path @ [List.hd mappings] in
             S.read s path >>= function
             | Error exn ->
                let err = Printexc.to_string exn in
                Log.err (fun f -> f "list %s failed: %s" (String.concat "/" path) err);
                return_none
             | Ok v ->
                let exp = Int64.of_string v in
                let mapping = mappings |> List.hd |> mapping_of_string in
                return_some (exp, mapping)) None paths

    >>= fun mapping_opt -> sanitize (s, n, q)
    >>= fun () -> return mapping_opt


  let delete ((s, _, _) as t) prot ~internal_lookup ~external_lookup =
    let root = string_of_protocol prot in
    let paths = [
      [root; "inbound"; string_of_mapping external_lookup];
      [root; "outbound"; string_of_mapping internal_lookup]] in

    let rec delete_files parent files =
      Lwt_list.iter_s (fun file ->
        let key = parent @ [file] in
        S.remove s key >|= ignore) files in

    Lwt_list.iter_s (fun parent ->
      S.list s ~parent () >>= function
      | Error _ -> return_unit
      | Ok files -> delete_files parent files) paths
    >>= fun () -> return t


  (********** operations about ports of request source **********)
  (* only knowing ports of request sources, could we delete corresponding entries in the NAT *)
  (* here src is external third party, and dst is the endpoint on the external interface of the NAT *)
  let dir_of_source_ports (src_ip, dst) =
    let dir = "source_ports" in
    let subdir = Printf.sprintf "%s_%s" (Ipaddr.to_string src_ip) (string_of_endpoint dst) in
    [dir; subdir]

  let key_of_source_port ((src_ip, src_port), dst) =
    dir_of_source_ports (src_ip, dst) @ [src_port |> string_of_int]

  let add_source_port (t, _, _) mapping =
    let key = key_of_source_port mapping in
    S.update t key "" >>= function
    | Ok () -> return_unit
    | Error exn ->
       Log.err (fun f -> f "add_source_port: %s" (Printexc.to_string exn));
       return_unit

  let list_source_ports (t, _, _) (ip, dst) =
    let parent = dir_of_source_ports (ip, dst) in
    S.list t ~parent () >>= function
    | Ok ports -> return @@ List.map int_of_string ports
    | Error exn ->
       Log.err (fun f -> f "list_source_ports: %s" (Printexc.to_string exn));
       return_nil

  let remove_source_ports (t, _, _) (ip, dst) =
    let key = dir_of_source_ports (ip, dst) in
    S.remove_rec t key >>= function
    | Ok () -> return_unit
    | Error exn ->
       Log.err (fun f -> f "remove_sourcd_ports: %s" (Printexc.to_string exn));
       return_unit


  (************ operations about new entries inserted by gatekeeper ****************)
  (* src is external third party, dst is endpoint on external interface of NAT, and final_dst is the endpoint
     of data holding unikernel behind the NAT *)
  let dir_of_inserted_entris = ["entries_inserted"]

  let key_of_inserted_entry (src_ip, dst) =
    let file = Printf.sprintf "%s_%s" (Ipaddr.to_string src_ip) (string_of_endpoint dst) in
    dir_of_inserted_entris @ [file]

  let add_entry (t, _, _) ((src_ip, dst), final_dst) =
    let key = key_of_inserted_entry (src_ip, dst) in
    let value = string_of_endpoint final_dst in
    S.update t key value >>= function
    | Ok () -> return_unit
    | Error exn ->
       Log.err (fun f -> f "add_entry: %s" (Printexc.to_string exn));
       return_unit

  let read_entry (t, _, _) (src_ip, dst) =
    let key = key_of_inserted_entry (src_ip, dst) in
    S.read t key >>= function
    | Ok value -> return_some @@ endpoint_of_string value
    | Error _ ->
       Log.info (fun f -> f "read_entry: no value %s -> %s"
                            (Ipaddr.to_string src_ip)
                            (string_of_endpoint dst));
       return_none

  let remove_entry (t, _, _) (src_ip, dst) =
    let key = key_of_inserted_entry (src_ip, dst) in
    S.remove t key >>= function
    | Ok () -> return_unit
    | Error exn ->
       Log.err (fun f -> f "remove_entry: %s" (Printexc.to_string exn));
       return_unit

end


module M = struct
  module Table = Storage
  include Nat_rewrite.Make(Table)
end
