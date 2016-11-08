#!/bin/bash -ex

mirage clean || true
mirage configure --t xen --no-opam --internal-ip 192.168.252.2 --internal-netmask 192.168.252.0/24 --external-ip 10.0.0.2 --external-netmask 10.0.0.0/24 --external-gateway 10.0.0.1 --persist-ip 10.0.0.1 --persist-port 20001 --logs *:info
mirage build
