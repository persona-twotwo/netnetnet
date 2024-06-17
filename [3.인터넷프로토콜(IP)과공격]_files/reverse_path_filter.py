#!/bin/env python3

from scapy.all import *

src_ip = '192.168.70.7'
#src_ip = '10.9.0.105'
#src_ip = '192.168.60.7'
dst_ip = '192.168.60.5'

ip = IP(src=src_ip, dst=dst_ip)
print("spoofed echo request sent......")
send(ip/ICMP())

