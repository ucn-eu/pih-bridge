open Mirage

let arg name opt =
  Key.create name @@ Key.Arg.required Key.Arg.string (Key.Arg.info [opt])

let external_ip = arg "external_ip" "external-ip"
let internal_ip = arg "internal_ip" "internal-ip"
let internal_netmask = arg "internal_netmask" "internal-netmask"
let external_gateway = arg "external_gateway" "external-gateway"
let external_netmask = arg "external_netmask" "external-netmask"

let operation_ip = arg "operation_ip" "operation-ip"
let gatekeeper_ip = arg "gatekeeper_ip" "gatekeeper-ip"
let gatekeeper_port =
    Key.create "gatekeeper_port" @@
      Key.Arg.required Key.Arg.int (Key.Arg.info ["gatekeeper-port"])

let persist_ip = arg "persist_ip" "persist-ip"
let persist_port = arg "persist_port" "persist-port"

let keys = Key.[
  abstract external_ip;
  abstract internal_ip;
  abstract external_netmask;
  abstract internal_netmask;
  abstract external_gateway;

  abstract operation_ip;
  abstract gatekeeper_ip;
  abstract gatekeeper_port;

  abstract persist_ip;
  abstract persist_port;
]

let main = foreign "Dyn_nat.Main" (clock @-> time @-> network @-> network
                                   @-> http @-> kv_ro
                                   @-> conduit @-> resolver @-> job)

let manage_config =
  let i = Ipaddr.V4.of_string_exn in
  {
    address = i "10.0.0.3";
    netmask = i "255.255.255.0";
    gateways = [i "10.0.0.1"];
  }

(* 0 is usually the bridge with other stuff on it *)
(* so the "first" vif offered to us will be a "management" interface *)
let stack = direct_stackv4_with_static_ipv4 (netif "0") manage_config

let conduit_impl = conduit_direct ~tls:true stack
let resolver_impl = resolver_dns stack
let http = http_server conduit_impl

(* netif actually needs an integer, shoved
into a string, which maps to a device ID number assigned by Xen, to do anything
helpful when xen is the target.  Stuff that can't be turned into an int
is silently dropped in that case and we just get the first Xen network iface. *)

let primary_netif = (netif "1")
let secondary_netif = (netif "2")

let key = crunch "tls"

let () =
  let packages = [
    "mirage-nat";
    "mirage-logs";
    "ezjsonm"] in
  let libraries = [
    "pih-store";
    "mirage-xen";
    "tcpip.ethif";
    "tcpip.ipv4";
    "tcpip.udp";
    "tcpip.tcp";
    "mirage-nat";
    "mirage-profile";
    "ezjsonm"] in
  register ~packages ~libraries ~keys "pih-bridge" [
    main $ default_clock $ default_time
    $ primary_netif $ secondary_netif
    $ http $ key
    $ conduit_impl $ resolver_impl
  ]
