#!/bin/bash -ex

mirage clean || true
mirage configure --t xen --no-opam --internal-ip 192.168.252.2 --internal-netmask 255.255.255.0 --external-ip 10.0.0.2 --external-netmask 255.255.255.0 --external-gateway 10.0.0.1 --operation-ip 10.0.0.3 --gatekeeper-ip 10.0.0.254 --gatekeeper-port 8080 --persist-ip 10.0.0.1 --persist-port 10001
mirage build
