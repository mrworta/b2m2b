#! /usr/bin/env python3
# 
# Selective BroadCast relay
# v0.3 / MrWorta
# - Requires tcpdump, impacket and pcapy
# - No error handling yet
#
import struct
import pcapy
from impacket.ImpactPacket import *
from impacket.ImpactDecoder import *
from socket import *

# Do some init stuff
# 0 = Nothing, except critical errors.
# 1 = Counters
# 9 = Gimmiallyouhave.
VERBOSE = 1
#
# VLAN's relayed TO. Input is taken from any VLAN.
# Loop protection is applied. 
#
# You can provide a VLANS list and/or use 
# vlan auto-learning (if relay first sees a vlan, it is added to the list).
#
#VLANS = [10,11,12,13,14,15,16,17,18,19,20]
#
VLANS = [15,20,5]
VLANS_BLACKLIST = [666,667]
LEARN_VLANS = True
#
#
OWN_IF = "ens224"
USE_PROM = True
MTU = 1500
LAZY = 100
#
# Portfilter can be customized:
PACKET_FILTER = "udp and broadcast and dst portrange 1024-65535"
#
########################################

# Open Capture Device and set filter:
cap = pcapy.open_live(OWN_IF, MTU, USE_PROM, LAZY)
cap.setfilter(PACKET_FILTER)

# Open output Device as raw:
s = socket(AF_PACKET, SOCK_RAW)
s.bind((OWN_IF, 0))

cnt_in = 0
cnt_out = 0

def pkt(hdr, data):
	global cnt_in	
	global cnt_out

	# Dissect the packet:
	eth = EthDecoder().decode(data)

	try:
		# Pop/Push Tag to test/read 802.1q:
		tag = eth.pop_tag()
		in_vlan = tag.get_vid()
		eth.push_tag(tag)
	except IndexError:
		# (un)Tagging impossible. Skip this packet.
		return

        if (in_vlan in VLANS_BLACKLIST): 
		return

	# Handle VLAN learning:	
	if LEARN_VLANS and not (in_vlan in VLANS): 
		VLANS.append(in_vlan)	
		
		if VERBOSE > 0: 
				sys.stdout.flush()
				print chr(13),"Added VLAN:",in_vlan,chr(13)
				sys.stdout.flush()

	cnt_in += 1

	# Debugging
	if VERBOSE > 2: 
		sys.stdout.write('i')
		if VERBOSE > 4: sys.stdout.write(str(in_vlan))
		sys.stdout.flush()
	
	# To the dirty work:

	for out_vlan in VLANS:
		if (in_vlan == out_vlan): continue

		# Remove old tag and add new one:
		tag = eth.pop_tag()
		tag.set_vid(out_vlan)
		eth.push_tag(tag)

		try:
			# Will it blend?
			s.send(eth.get_packet())
		except:
			print "E"
			continue

		cnt_out += 1

		# Debugging
		if VERBOSE > 5: 
			sys.stdout.write(">"+str(out_vlan))
			sys.stdout.flush()

	# Debugging / Counters
	if VERBOSE > 5: print "."
	if VERBOSE == 1: 
		sys.stdout.write("IN: "+str(cnt_in)+" OUT: "+str(cnt_out)+chr(13))
                sys.stdout.flush()

try:
	cap.loop(-1, pkt)
except (KeyboardInterrupt, SystemExit):
	print "..."
	print "Exiting after ",cnt_in,"in /",cnt_out,"out packets."
	sys.exit()
