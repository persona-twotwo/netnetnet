#!/usr/bin/python3
from scapy.all import *

print("SENDING SPOOFED UDP PACKET.........")
ip = IP(src="10.9.0.6", dst="10.9.0.5")
udp = UDP(sport=8888, dport=9090)
data = "Hello UDP~~\n"
pkt = ip/udp/data
pkt.show()
send(pkt, verbose=0)


