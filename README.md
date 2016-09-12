# PIH Bridge

NAT-like infrastructure that provides dynamic connectivity management service between the Internet and [unikernels (and VMs) on PIH]. For its NAT-like facet, the outbound session traffic from unikernels to outside world could be translated automatically, the bridge would be transparent to those traffic. For its dynamic connectivity management facet, there is an open port for the connectivity manager to insert new translation rules. Within the context of PIH, the manager would be the [pih-gatekeeper], who could insert new rules to allow authenticated and user-approved external client to initiate new sessions towards the data holding unikernels behind the bridge. Besides insertion, the rules could also be removed by the manager, hence the packets from the traffic will be discarded siliently once the removal operation is done.


### Build and Run

As the name suggested, this infrastructre connects two nework together. One is outside facing, where sites the [pih-gatekeeper] and external requests could come through, and the other one is the internal local network, where we find all the data serving unikernels. And the bridge would have interfaces on both networks. In order to run/test this infrastructure, you may need configure your network properly beforehand. I used the script [net_conf.sh] on Ubuntu 14.04 TLS. The goal is to have two network bridges set up and configured. Afterwards, you could use the script [build.sh] to configure and build the pih-bridge unikernel.

As with [pih-gatekeeper], the bridge would also persist its runtime configurations *(basically all the translations rules)* somewhere in an irmin server. The endpoint information of the irmin server get passed in by `mirage config` command from [build.sh]. Set up the server before the invocation of the unikernel.

**BUILDING TRAPS**: 
As the bridge would have three network interfaces *(two on each network bridge, one for insertion of new translation rules)*, you could see `netif "0"`, `netif "1"`, `netif "2"` in `config.ml` accordingly. But after configuration phase, in the auto-generated main file `main.ml`, these information get lost, very probably, you are going to end up with three network devices attached to the same interface, as you could find these snippets in the main file, and `Key_gen.network ()` evaluates to the same interface:
```ocaml
let net11 = lazy (
  Netif.connect (Key_gen.network ())
  )
let net12 = lazy (
  Netif.connect (Key_gen.network ())
  )
let net13 = lazy (
  Netif.connect (Key_gen.network ())
  )
```
For temporary workaround, before going into the building phase, you may need change the main file manually, providing the correct interface index to the `connect` function call, as:
```ocaml
let net11 = lazy (
  Netif.connect "0"
  )
let net12 = lazy (
  Netif.connect "1"
  )
let net13 = lazy (
  Netif.connect "2"
  )
```
After this, you would get a kernel working as expected by simply running `mirage build`.

Another point worth mentioning, if you want to invoke the unikernel through `xl` commond utility, you may need some modification to the configfile `config.ml` as well. Changing the `vif` field as following
```
vif = [ 'bridge=br0', 'bridge=br0', 'bridge=br1' ]
```
would get each network interface attached on the right network bridge on your machine.

[unikernels (and VMs) on PIH]:https://github.com/sevenEng/pih-store-instance
[pih-gatekeeper]:https://github.com/sevenEng/pih-gatekeeper
[net_conf.sh]:./net_conf.sh
[build.sh]:./build.sh
