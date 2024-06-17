#!/bin/env python3
import socket

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.connect(('10.9.0.5', 9090))

tcp.sendall(b"Hello Server!\n")
data = tcp.recv(1024)
print(data)

tcp.sendall(b"Hello Again!\n")
data = tcp.recv(1024)
print(data)

tcp.close()

