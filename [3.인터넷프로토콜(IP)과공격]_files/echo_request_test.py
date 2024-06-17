#!/bin/env python3

from scapy.all import *

ip = IP(dst="8.8.8.8")
icmp = ICMP() # By default, echo reqeust msg.
pkt = ip/icmp

#print("spoofed echo request sent......")
reply = sr1(pkt)
print("ICMP reply.........")
print("Source IP : ", reply[IP].src)
print("Destination IP : ", reply[IP].dst)
