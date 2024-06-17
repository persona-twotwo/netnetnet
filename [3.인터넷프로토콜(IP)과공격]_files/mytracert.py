#!/bin/env python3

import sys
from scapy.all import *

print("SENDING ICMP PACKET.........")
a = IP()
#a.dst = '223.130.192.248' # www.naver.com
a.dst = '203.237.99.12' # www.naver.com

b = ICMP()

#Choose the TTL value from 1 to 19
for TTL in range(1, 20):
  a.ttl = TTL
  h = sr1(a/b, timeout=2, verbose=0)
  if h is None:
    print("Router: *** (hops = {})".format(TTL))
  else :
    print("Router: {} (hops = {})".format(h.src, TTL))
