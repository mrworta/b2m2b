#!/usr/bin/python
import socket

MCAST_GRP = '239.66.66.66'
MCAST_PORT = 27001

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
sock.sendto("myPack", (MCAST_GRP, MCAST_PORT))
