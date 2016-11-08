#!/bin/bash

MASQSRC=10.0.0.0/24
BR0IP=10.0.0.1/24
BR0MAC=aa:bb:cc:dd:ee:b0

BR1IP=192.168.252.1/24
BR1MAC=aa:bb:cc:dd:ee:b1

brctl addbr br0
ip link set dev br0 address $BR0MAC
ip addr add $BR0IP dev br0
ip link set dev br0 up

brctl addbr br1
ip link set dev br1 address $BR1MAC
ip addr add $BR1IP dev br1
ip link set dev br1 up

sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o eth0 -s $MASQSRC -j MASQUERADE


iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 8443 -j DNAT --to 10.0.0.254:8443
iptables -A FORWARD -p tcp -d 10.0.0.254 --dport 8080 -j ACCEPT

iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 10003 -j DNAT --to 10.0.0.2:10003
iptables -A FORWARD -p tcp -d 10.0.0.2 --dport 10003 -j ACCEPT

iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 10004 -j DNAT --to 10.0.0.2:10004
iptables -A FORWARD -p tcp -d 10.0.0.2 --dport 10004 -j ACCEPT
