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
iptables -t nat -A POSTROUTING -o wlan0 -s $MASQSRC -j MASQUERADE
