#!/bin/bash
#performs setup on a node, dropping necessary paths and setting
#up a new default path to the first-hop router

first_hop = $1

sudo route add -host 192.168.253.1 gw 192.168.1.254
sudo route add -host 192.168.252.1 gw 192.168.1.254
sudo route add -host 192.168.253.3 gw 192.168.1.254
sudo route del default gw 192.168.1.254
sudo route add default gw first_hop
