#!/usr/bin/python3

from scapy.all import *

def process_packet(pkt):
  #hexdump(pkt)
  pkt.show()
  print("----------------------------")
  
f = 'udp and dst portrange 50-55 or icmp'

sniff(iface='br-6378768f125b', filter=f, prn=process_packet)
