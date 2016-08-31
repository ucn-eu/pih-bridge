(*most part copied from yomimono/simple-nat /simple_nat.ml*)
open V1_LWT
open Lwt

let src_log = Logs.Src.create "DYN_NAT"
module Log = (val Logs.src_log src_log : Logs.LOG)

module Main (Clock: V1.CLOCK) (Time: V1_LWT.TIME)
    (PRI: NETWORK) (SEC: NETWORK)
    (HTTP: Cohttp_lwt.Server) (KEYS: KV_RO)
    (CONDUIT: Conduit_mirage.S) (RESOLVER: Resolver_lwt.S) = struct

  module Logs_reporter = Mirage_logs.Make(Clock)

  module ETH = Ethif.Make(PRI)
  module A = Arpv4.Make(ETH)(Clock)(Time)
  module I = Ipv4.Make(ETH)(A)
  type direction = | Source | Destination

  module Nat_clock = struct
    let now () = Clock.time () |> Int64.of_float
  end

  module Nat_rewrite = Mirage_nat_irmin.Make(Nat_clock)

  let inspect_frame ~fname frame =
    let to_string_mac b = b |> Macaddr.of_bytes_exn |> Macaddr.to_string in
    let dmac = Ethif_wire.copy_ethernet_dst frame |> to_string_mac in
    let smac = Ethif_wire.copy_ethernet_src frame |> to_string_mac in
    let v4_frame = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    Log.info (fun f -> f "[%s] MAC %s -> %s" fname smac dmac)

  let inspect_packet ~fname frame =
    let p = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    let header = Cstruct.set_len p Ipv4_wire.sizeof_ipv4 in
    let csum = Tcpip_checksum.ones_complement header in
    let dip = Ipv4_wire.get_ipv4_dst p |> Ipaddr.V4.of_int32 |> Ipaddr.V4.to_string in
    let sip = Ipv4_wire.get_ipv4_src p |> Ipaddr.V4.of_int32 |> Ipaddr.V4.to_string in
    Log.info (fun f -> f "[%s] IP  %s -> %s, CSUM %d" fname sip dip csum)

  let eth_input mac ~arpv4 ~ipv4 t frame =
    let open Ethif_packet in
    let of_interest dest =
      Macaddr.compare dest mac = 0 || not (Macaddr.is_unicast dest)
    in
    match Unmarshal.of_cstruct frame with
    | Ok (header, payload) when of_interest header.destination ->
      begin
        let open Ethif_wire in
        match header.ethertype with
        | ARP -> arpv4 payload
        | IPv4 -> ipv4 frame
        | IPv6 -> return_unit
      end
    | Ok _ -> Lwt.return_unit
    | Error s -> Log.debug (fun f -> f "Dropping Ethernet frame: %s" s);
      Lwt.return_unit


  let listen netif ethif a push =
    (* ingest packets *)
    let mac = PRI.mac netif in
    PRI.listen netif
      (eth_input mac ethif
        ~arpv4:(A.input a)
        ~ipv4:(fun frame ->
          push (Some frame); return_unit))

  module PortSet = Set.Make(struct
    type t = Mirage_nat.port
    let compare = Pervasives.compare
  end)

  let external_ports = ref PortSet.empty
  let internal_ports = ref PortSet.empty
  let get_fresh_port set =
    let rec aux () =
      let p = Random.int 65535 in
      if p < 1024 || PortSet.mem p set then aux ()
      else p in
    aux ()

  let allow_nat_traffic table frame ip =
    let rec stubborn_insert table frame ip n =
      (* TODO: in the unlikely event that no port is available, this
         function will never terminate (this is really a tcpip todo) *)
      let open Nat_rewrite in
      add_nat table frame (ip, n) >>= function
      | Ok ->
         external_ports := PortSet.add n !external_ports;
         Lwt.return (Some ())
      | Unparseable -> Lwt.return None
      | Overlap -> stubborn_insert table frame ip (get_fresh_port !external_ports)
    in
    (* TODO: connection tracking logic *)
    stubborn_insert table frame ip (get_fresh_port !external_ports)

  let new_entries = ref []

  let add_new_entry (src_dst_pair, dst) =
    Log.info (fun f -> f "new translation rule waiting to be inserted");
    new_entries := (src_dst_pair, dst) :: !new_entries

  let entry_inserted pair =
    Log.info (fun f -> f "new translation rule inserted");
    let nl = List.filter (fun (k,_) -> k <> pair) !new_entries in
    new_entries := nl

  let is_new_entry pair =
    List.mem_assoc pair !new_entries


  let headers = Cohttp.Header.of_list [
    "Strict-Transport-Security", "max-age=31536000";
    "Access-Control-Allow-Origin", "*"]

  (* use Nat_rewrite.add_redirect, in the frame the dst should be
     a address-port pair of the external interface, while other_xl_ip/other_xl_port
     is a pair of the internal interface, and final_destination(ip/pair) is the
     real ip/port of the unikernel behind the NAT,
     so if a request is allowed after identify authentication, a ip/port pair on
     the external interface should be returned as connect point *)
  let manage_entry (nat_t, external_ip) () =
    let callback (_,cid) req body =
      let uri = Cohttp.Request.uri req in
      let cid = Cohttp.Connection.to_string cid in
      Log.info (fun f -> f  "[%s] serving %s." cid (Uri.to_string uri));
      let path = Uri.path uri in
      if path = "/insert" then
        Cohttp_lwt_body.to_string body >>= fun b ->
        Lwt.catch (fun () -> Lwt.wrap (fun () ->
          let req_body = Ezjsonm.(from_string b |> value |> get_dict) in
          let ip =
            List.assoc "ip" req_body
            |> Ezjsonm.get_string
            |> Ipaddr.V4.of_string_exn in
          let port =
            List.assoc "port" req_body
            |> Ezjsonm.get_int in
          let dst_ip =
            List.assoc "dst_ip" req_body
            |> Ezjsonm.get_string
            |> Ipaddr.V4.of_string_exn in
          let dst_port =
            List.assoc "dst_port" req_body
            |> Ezjsonm.get_int in
          Log.info (fun f ->
            f "new entry %s:%d -> %s:%d to be inserted"
            (Ipaddr.V4.to_string     ip)     port
            (Ipaddr.V4.to_string dst_ip) dst_port);
          (ip, port), (dst_ip, dst_port)) >>= fun (src, dst) ->

          let nat_dst_port = get_fresh_port !external_ports in
          add_new_entry ((src, (external_ip, nat_dst_port)), dst);
          let body = Ezjsonm.([
            "ip",   external_ip |> Ipaddr.V4.to_string |> string;
            "port", nat_dst_port |> int]
             |> dict
             |> to_string
             |> Cohttp_lwt_body.of_string) in
          HTTP.respond ~headers ~status:`OK ~body ())
          (fun exn ->
           let body = Printexc.to_string exn in
           HTTP.respond_error ~headers ~status:`Bad_request ~body ())
      else if path = "/remove" then
        Cohttp_lwt_body.to_string body >>= fun b ->
        Lwt.catch (fun () ->
          let req_body = Ezjsonm.(from_string b |> value |> get_dict) in
          let src_ip =
            List.assoc "src_ip" req_body
            |> Ezjsonm.get_string
            |> Ipaddr.of_string_exn in
          let src_port =
            List.assoc "src_port" req_body
            |> Ezjsonm.get_int in
          let dst_ip =
            List.assoc "dst_ip" req_body
            |> Ezjsonm.get_string
            |> Ipaddr.of_string_exn in
          let dst_port =
            List.assoc "dst_port" req_body
            |> Ezjsonm.get_int in
          Log.info (fun f ->
            f "entry %s:%d -> %s:%d to be removed"
            (Ipaddr.to_string src_ip) src_port
            (Ipaddr.to_string dst_ip) dst_port);
          return @@ ((src_ip, src_port), (dst_ip, dst_port)) >>= fun (source, destination) ->
          let external_lookup = source, destination in
          Nat_rewrite.Table.lookup nat_t Mirage_nat.Tcp ~source ~destination >>= function
          | None ->
             let internal_lookup = external_lookup in
             Nat_rewrite.Table.delete nat_t Mirage_nat.Tcp ~external_lookup ~internal_lookup
             >>= fun _ -> HTTP.respond ~headers ~status:`OK ~body ()
          | Some (_, (mapping_src, mapping_dst)) ->
             let internal_lookup = mapping_dst, mapping_src in
             Nat_rewrite.Table.delete nat_t Mirage_nat.Tcp ~external_lookup ~internal_lookup
             >>= fun _ -> HTTP.respond ~headers ~status:`OK ~body ())
          (fun exn ->
           let body = Printexc.to_string exn in
           HTTP.respond_error ~headers ~status:`Bad_request ~body ())

      else
        HTTP.respond_error ~headers ~status:`Not_found ~body:"" ()
    in
    let conn_closed (_,cid) =
      let cid = Cohttp.Connection.to_string cid in
      Log.info (fun f -> f "[%s] closing" cid)
    in
    HTTP.make ~conn_closed ~callback ()


  let stubborn_insert_redirect t frame pair internal_ip =
    let other_xl_ip = internal_ip in
    let final_dst_ip, final_dst_port = List.assoc pair !new_entries in
    let rec aux () =
      let other_xl_port = get_fresh_port !internal_ports in
      let other_endp = other_xl_ip, other_xl_port
      and final_endp = Ipaddr.V4 final_dst_ip, final_dst_port in
      let open Nat_rewrite in
      add_redirect t frame other_endp final_endp >>= function
      | Ok ->
         entry_inserted pair;
         return_unit
      | Overlap -> aux ()
      | Unparseable -> Lwt.fail (Failure "unparseable frame") in
    aux ()


  let insert_new_entry t frame int_ip fn =
    let eth_payload = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    let src_ip =
      Ipv4_wire.get_ipv4_src eth_payload
      |> Ipaddr.V4.of_int32 in
    let dst_ip =
      Ipv4_wire.get_ipv4_dst eth_payload
      |> Ipaddr.V4.of_int32 in
    let proto = Ipv4_wire.get_ipv4_proto eth_payload in
    let ip_payload = Cstruct.shift eth_payload Ipv4_wire.sizeof_ipv4 in
    let src_port, dst_port =
      match Ipv4_packet.Unmarshal.int_to_protocol proto with
      | None -> -1, -1
      | Some `TCP -> Tcp.Tcp_wire.get_tcp_src_port ip_payload,
                     Tcp.Tcp_wire.get_tcp_dst_port ip_payload
      | Some `UDP -> Udp_wire.get_udp_dest_port ip_payload,
                     Udp_wire.get_udp_dest_port ip_payload
      | Some _ -> -1, -1 in
    if src_port = -1 then Lwt.fail (Failure "src port unavailable")
    else
      let pair = (src_ip, src_port), (dst_ip, dst_port) in
      if is_new_entry pair then
        stubborn_insert_redirect t frame pair int_ip
      else return_unit


  let nat external_ip internal_ip nat_table (direction : direction)
      in_queue out_push =
    let rec aux frame =
      let open Mirage_nat in
      (* typical NAT logic: traffic from the internal "trusted" interface gets
         new mappings by default; traffic from other interfaces gets dropped if
         no mapping exists (which it doesn't, since we already checked) *)
      Nat_rewrite.translate nat_table frame >>= fun f ->
      match direction, f with
      | Destination, Untranslated ->
         insert_new_entry nat_table frame internal_ip aux
      | Destination, (Translated dst) ->
         (* heartbeat to demonstrate liveness *)
         return (out_push (Some (dst, frame)))
      | Source, (Translated dst) ->
         return (out_push (Some (dst, frame)))
      | Source, Untranslated ->
         Log.info (fun f -> f "add_nat_traffic");
         inspect_frame ~fname:"nat" frame;
         inspect_packet ~fname:"nat" frame;
        (* mutate nat_table to include entries for the frame *)
        allow_nat_traffic nat_table frame external_ip >>= function
        | Some () ->
          (* try rewriting again; we should now have an entry for this packet *)
          aux frame
        | None ->
          (* this frame is hopeless! *)
          return_unit
    in
    let rec process () =
      Lwt_stream.next in_queue >>= aux >>= process
    in
    process ()


  let send_packets_ip i q =
    let fname = "send" in
    let aux (_, frame) =
      inspect_frame ~fname frame;
      inspect_packet ~fname frame;
      I.writev i frame [] in
    let rec process () =
      Lwt_stream.next q >>= aux >>= process in
    process ()


  let with_filter_push check push = function
    | Some frame ->
       if check frame then begin
           push (Some frame) end
       else ()(*begin
       Log.info (fun f -> f "fail the prefix check!");
       inspect_packet frame end*)
    | None -> ()


  let check_prefix netmask addr frame =
    let p = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    let dst = Ipv4_wire.get_ipv4_dst p |> Ipaddr.V4.of_int32 in
    let src = Ipv4_wire.get_ipv4_src p |> Ipaddr.V4.of_int32 in
    let subnet = Ipaddr.V4.Prefix.of_netmask netmask addr in
    Ipaddr.V4.Prefix.(mem dst subnet || mem src subnet)


  module X509 = Tls_mirage.X509(KEYS)(Clock)


  let tls_init kv =
    X509.certificate kv `Default >>= fun cert ->
    let conf = Tls.Config.server ~certificates:(`Single cert) () in
    Lwt.return conf

  let start _clock _time pri sec http keys conduit resolver =
    Logs.(set_level (Some Info));
    Logs_reporter.(create () |> run) @@ fun () ->

    tls_init keys >>= fun cfg ->
    let tcp = `TCP 8080 in
    let tls = `TLS (cfg, `TCP 8443) in

    let (pri_in_queue, pri_in_push) = Lwt_stream.create () in
    let (pri_out_queue, pri_out_push) = Lwt_stream.create () in
    let (sec_in_queue, sec_in_push) = Lwt_stream.create () in
    let (sec_out_queue, sec_out_push) = Lwt_stream.create () in

    (* or_error brazenly stolen from netif-forward *)
    let or_error name fn t =
      fn t
      >>= function
      | `Error e -> fail (Failure ("error starting " ^ name))
      | `Ok t -> Log.info (fun f -> f "%s connected." name);
                 return t
    in

    (* get network configuration from bootvars *)
    let addr = Ipaddr.V4.of_string_exn in
    let internal_ip = addr @@ Key_gen.internal_ip () in
    let internal_netmask = addr @@ Key_gen.internal_netmask () in
    let external_ip = addr @@ Key_gen.external_ip () in
    let external_netmask = addr @@ Key_gen.external_netmask () in
    let external_gateway = addr @@ Key_gen.external_gateway () in

    let operation_ip = Key_gen.operation_ip () in
    let gatekeeper_ip = Key_gen.gatekeeper_ip () in
    let gatekeeper_port = Key_gen.gatekeeper_port () in

    (* initialize interfaces *)
    or_error "primary interface" ETH.connect pri >>= fun ethif1 ->
    or_error "secondary interface" ETH.connect sec >>= fun ethif2 ->

    or_error "primary arp" A.connect ethif1 >>= fun arp1 ->
    or_error "secondary arp" A.connect ethif2 >>= fun arp2 ->

    (* set up ipv4 on interfaces so ARP will be answered *)
    or_error "ip for primary interface" (I.connect ethif1) arp1 >>= fun ext_i ->
    or_error "ip for secondary interface" (I.connect ethif2) arp2 >>= fun int_i ->
    I.set_ip ext_i external_ip >>= fun () ->
    I.set_ip_netmask ext_i external_netmask >>= fun () ->
    I.set_ip int_i internal_ip >>= fun () ->
    I.set_ip_netmask int_i internal_netmask >>= fun () ->
    I.set_ip_gateways ext_i [ external_gateway ] >>= fun () ->

    let filtered_pri_in_push =
      let pri_prefix = check_prefix external_netmask external_ip in
      with_filter_push pri_prefix pri_in_push in

    let filtered_sec_in_push =
      let sec_prefix = check_prefix internal_netmask internal_ip in
      with_filter_push sec_prefix sec_in_push in

    (*
    let heartbeat_liveness ip =
      let module Client = Cohttp_mirage.Client in
      let ctx = Client.ctx resolver conduit in
      let host = gatekeeper_ip
      and port = gatekeeper_port in
      let path = Printf.sprintf "/alive/%s" ip in
      let uri = Uri.make ~scheme:"http" ~host ~port ~path () in
      Client.get ~ctx uri >>= fun (res, _) ->
      let status = Cohttp.Response.status res in
      if status = `OK then return_unit
      else begin
          let s = Cohttp.Code.string_of_status status in
          Log.warn (fun f -> f "heartbeat liveness %s: %s" ip s);
          return_unit end in

    let rec heartbeat_loop () =
      OS.Time.sleep 15.0 >>= fun () ->
      heartbeat_liveness operation_ip >>= fun () ->
      heartbeat_loop () in *)

    let () =
      Lwt.async_exception_hook := (fun exn ->
        Log.err (fun f -> f "async exception: %s" (Printexc.to_string exn))) in

    (* TODO: provide hooks for updates to/dump of this *)
    let persist_host = Key_gen.persist_ip () in
    let persist_port = Key_gen.persist_port () |> int_of_string in
    let persist_uri = Uri.make ~scheme:"http" ~host:persist_host ~port:persist_port () in
    let conf = Mirage_nat_irmin.({resolver; conduit; uri = persist_uri; owner = "ucn.bridge"}) in
    Nat_rewrite.empty conf >>= fun nat_t ->

    Lwt.choose [
        (* packet intake *)
        (listen pri ethif1 arp1 filtered_pri_in_push);
        (listen sec ethif2 arp2 filtered_sec_in_push);

        (* TODO: ICMP, at least on our own behalf *)

        (* address translation *)

        (* for packets received on xenbr1 ("internal"), rewrite source address/port
       before sending packets out the primary interface *)
        (nat (Ipaddr.V4 external_ip) (Ipaddr.V4 internal_ip) nat_t Source sec_in_queue pri_out_push);

        (* for packets received on the first interface (xenbr0/br0 in examples,
       which is an "external" world-facing interface),
       rewrite destination addresses/ports before sending packet out the second
       interface *)
        (nat (Ipaddr.V4 external_ip) (Ipaddr.V4 internal_ip) nat_t Destination pri_in_queue sec_out_push);

        (* packet output *)
        (*(send_packets c pri arp1 pri_out_queue (Some (Ipaddr.V4 external_gateway)));
        (send_packets c sec arp2 sec_out_queue None)*)
        send_packets_ip ext_i pri_out_queue;
        send_packets_ip int_i sec_out_queue;

        http tcp @@ manage_entry (nat_t, external_ip) ();
      ]

  end
