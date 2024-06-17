#!/usr/bin/python3
from scapy.all import *

IPpkt = IP(dst = '10.9.0.5', chksum = 0)
UDPpkt = UDP(dport = 9090, chksum = 0)
payload = "Hello Server\n"
pkt = IPpkt/UDPpkt/payload

# Save the packet data to a file
with open('ip.bin', 'wb') as f:
  f.write(bytes(pkt))
  
