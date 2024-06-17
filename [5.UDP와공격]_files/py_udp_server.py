#!/bin/env python3
import socket

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", 9090))

while True:
  data, addr = udp.recvfrom(1024)
  print("from {}: data {}".format(addr, data))
