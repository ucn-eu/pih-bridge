(*most part copied from yomimono/simple-nat /simple_nat.ml*)
open V1_LWT
open Lwt

let src_log = Logs.Src.create "NAT"
module Log = (val Logs.src_log src_log : Logs.LOG)

module Main (Clock: V1.CLOCK) (Time: V1_LWT.TIME)
    (PRI: NETWORK) (SEC: NETWORK)
    (HTTP: Cohttp_lwt.Server) (KEYS: KV_RO)= struct

  module Logs_reporter = Mirage_logs.Make(Clock)

  module ETH = Ethif.Make(PRI)
  module A = Arpv4.Make(ETH)(Clock)(Time)
  module I = Ipv4.Make(ETH)(A)
  type direction = | Source | Destination

  module Nat_clock = struct
    let now () = Clock.time () |> Int64.of_float
  end

  module Nat_rewrite = Mirage_nat_hashtable.Make(Nat_clock)(Time)

  let inspect_frame frame =
    let to_string_mac b = b |> Macaddr.of_bytes_exn |> Macaddr.to_string in
    let dmac = Ethif_wire.copy_ethernet_dst frame |> to_string_mac in
    let smac = Ethif_wire.copy_ethernet_src frame |> to_string_mac in
    let v4_frame = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    Log.info (fun f -> f "MAC %s -> %s" smac dmac)

  let inspect_packet frame =
    let p = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    let header = Cstruct.set_len p Ipv4_wire.sizeof_ipv4 in
    let csum = Tcpip_checksum.ones_complement header in
    let dip = Ipv4_wire.get_ipv4_dst p |> Ipaddr.V4.of_int32 |> Ipaddr.V4.to_string in
    let sip = Ipv4_wire.get_ipv4_src p |> Ipaddr.V4.of_int32 |> Ipaddr.V4.to_string in
    Log.info (fun f -> f "IP  %s -> %s, CSUM %d" sip dip csum)

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


  let allow_nat_traffic table frame ip =
    let rec stubborn_insert table frame ip port = match port with
      (* TODO: in the unlikely event that no port is available, this
         function will never terminate (this is really a tcpip todo) *)
      | n when n < 1024 ->
        stubborn_insert table frame ip (Random.int 65535)
      | n ->
        let open Nat_rewrite in
        add_nat table frame (ip, n) >>= function
        | Ok -> Lwt.return (Some ())
        | Unparseable -> Lwt.return None
        | Overlap -> stubborn_insert table frame ip (Random.int 65535)
    in
    (* TODO: connection tracking logic *)
    stubborn_insert table frame ip (Random.int 65535)

  let new_entries = ref []

  let insert_entry internal_ip () =
    (*TODO: auth the insert request*)
    let callback _ req body =
      let uri = Cohttp.Request.uri req in
      let path = Uri.path uri in
      if path = "/insert" then
        Cohttp_lwt_body.to_string body >>= fun b ->
        let req_pair = Ezjsonm.(from_string b |> value |> get_dict) in
        let ip = List.assoc "ip" req_pair |> Ezjsonm.get_string
                 |> fun s -> Ipaddr.V4 (Ipaddr.V4.of_string_exn s) in
        let port = List.assoc "port" req_pair |> Ezjsonm.get_string |> int_of_string in
        new_entries := ((ip, port), internal_ip) :: !new_entries;
        HTTP.respond ~status:`OK ~body:Cohttp_lwt_body.empty ()
      else
        HTTP.respond_error ~status:`Not_found ~body:"" ()
    in
    HTTP.make ~callback ()


  let add_new_entry t frame fn =
    let eth_payload = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    let src_ip =
      Ipv4_wire.get_ipv4_src eth_payload
      |> fun ip -> Ipaddr.V4 (Ipaddr.V4.of_int32 ip) in
    let proto = Ipv4_wire.get_ipv4_proto eth_payload in
    let ip_payload = Cstruct.shift eth_payload Ipv4_wire.sizeof_ipv4 in
    let src_port =
      match Ipv4_packet.Unmarshal.int_to_protocol proto with
      | None -> -1
      | Some `TCP -> Tcp.Tcp_wire.get_tcp_src_port ip_payload
      | Some `UDP -> Udp_wire.get_udp_dest_port ip_payload
      | Some _ -> -1 in
    if src_port = -1 then Lwt.fail (Failure "src port unavailable") else
      let ne = !new_entries in
      if List.mem_assoc (src_ip, src_port) ne then
        let translation_ip = List.assoc (src_ip, src_port) ne in
        allow_nat_traffic t frame translation_ip >>= function
        | None -> (*TODO: log the failer*) return_unit
        | Some () ->
           let less = List.filter (fun (pair, _) -> not (pair = (src_ip, src_port))) ne in
           let () = new_entries := less in
           fn frame
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
         add_new_entry nat_table frame aux >>= fun () ->
         Lwt.return_unit (* nothing in the table, drop it *)
      | _, (Translated dst) ->
        return (out_push (Some (dst, frame)))
      | Source, Untranslated ->
         Log.info (fun f -> f "add_nat_traffic");
         inspect_frame frame;
         inspect_packet frame;
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
    let aux (_, frame) =
      inspect_frame frame;
      inspect_packet frame;
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


  let start _clock _time pri sec http keys =
    Logs.(set_level (Some Info));
    Logs_reporter.(create () |> run) @@ fun () ->

    tls_init keys >>= fun cfg ->
    let tcp = `TCP 4433 in
    let tls = `TLS (cfg, tcp) in

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
    let fix = Ipaddr.V4.of_string_exn in
    let internal_ip = fix @@ Key_gen.internal_ip () in
    let internal_netmask = fix @@ Key_gen.internal_netmask () in
    let external_ip = fix @@ Key_gen.external_ip () in
    let external_netmask = fix @@ Key_gen.external_netmask () in
    let external_gateway = fix @@ Key_gen.external_gateway () in

    (* initialize interfaces *)
    or_error "primary interface" ETH.connect pri >>= fun ethif1 ->
    or_error "secondary interface" ETH.connect sec >>= fun ethif2 ->

    or_error "primary arp" A.connect ethif1 >>= fun arp1 ->
    or_error "primary arp" A.connect ethif2 >>= fun arp2 ->

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

    (* TODO: provide hooks for updates to/dump of this *)
    Nat_rewrite.empty () >>= fun nat_t ->

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

        http tls @@ insert_entry (Ipaddr.V4 internal_ip) ()
      ]

  end
