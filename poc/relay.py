#! /usr/bin/env python
# 
# Selective BroadCast relay
# v0.2 / MrWorta
# - Requires tcpdump, impacket and pcapy
# - No error handling yet
#
import struct
import pcapy
from impacket.ImpactPacket import *
from impacket.ImpactDecoder import *
from socket import *

# Do some init stuff
VERBOSE = 1

# VLAN's relayed TO. Input is taken from any VLAN.
# Loop protection is applied:
VLANS = [10,11,12,13,14,15,16,17,18,19,20]

OWN_IF = "eth0"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Ports can be customized:
PACKET_FILTER = "udp and (broadcast) and dst portrange 1024-65535"

########################################

cap = pcapy.open_live(OWN_IF, 1500, True, 100)
cap.setfilter(PACKET_FILTER)

s = socket(AF_PACKET, SOCK_RAW)
s.bind((OWN_IF, 0))

cnt_in = 0
cnt_out = 0

def pkt(hdr, data):
	global cnt_in	
	global cnt_out

	eth = EthDecoder().decode(data)
	try:
		tag = eth.pop_tag()
		in_vlan = tag.get_vid()
		eth.push_tag(tag)
	except IndexError:
		return

	cnt_in += 1

	if VERBOSE > 2: 
		sys.stdout.write('i')
		if VERBOSE > 4: sys.stdout.write(str(in_vlan))
		sys.stdout.flush()

	for out_vlan in VLANS:
		if (in_vlan == out_vlan): continue

		tag = eth.pop_tag()
		tag.set_vid(out_vlan)
		eth.push_tag(tag)

		try:
			s.send(eth.get_packet())
		except:
			print "E"
			continue

		cnt_out += 1
		if VERBOSE > 5: 
			sys.stdout.write(">"+str(out_vlan))
			sys.stdout.flush()


	if VERBOSE > 5: print "."
	if VERBOSE == 1: 
		sys.stdout.write("IN: "+str(cnt_in)+" OUT: "+str(cnt_out)+chr(13))
                sys.stdout.flush()

cap.loop(-1, pkt)
