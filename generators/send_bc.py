#!/usr/bin/python
import sys, time
from socket import *

BC_PORT = 27015

s = socket(AF_INET, SOCK_DGRAM)
s.bind(('10.2.2.254', 0))
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

while True:
	data = repr("fred")
	s.sendto(data, ('<broadcast>', BC_PORT))
	time.sleep(1)
