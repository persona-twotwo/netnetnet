#!/usr/bin/python3
from scapy.all import *

print("SENDING SPOOFED ICMP PACKET.........")
ip = IP(src="10.9.0.6", dst="10.9.0.5")
icmp = ICMP()
pkt = ip/icmp
pkt.show()
send(pkt, verbose=0)

