#!/usr/bin/python3

from scapy.all import *

pkt = sniff(iface='br-67c2985f8af6', filter='icmp or udp', count=10)

pkt.summary()

