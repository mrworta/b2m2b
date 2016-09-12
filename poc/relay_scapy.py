#! /usr/bin/env python
# 
# Selective BroadCast relay
# v0.1 / MrWorta
# - Requires tcpdump and python-scapy
# - No error handling yet
#
import socket, struct
from scapy.all import *
conf.use_pcap = True
import pcappy as pcap
import scapy.arch.pcapdnet

print conf.L2listen

# Do some init stuff
VERBOSE = 3
VLANS = [10,11,12,13,14,15,16,17,18,19,20]
OWN_IF = "eth0"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"

# The first part about ip and bc/mc is mandatory. Ports can be customized.
#PACKET_FILTER = "ip and (broadcast) and dst portrange 1024-65535"
PACKET_FILTER = "udp and (broadcast)"

def bridge_callback(pkt):
	
	# Handle all broadcast packets
	# Transform BC to MultiCast:
	if (pkt[Ether].dst == BCAST_MAC): 	
	
		try:
			in_vlan = pkt[Dot1Q].vlan
			if VERBOSE > 2: sys.stdout.write('i')
		except:
			return

		if VERBOSE > 5: print "IN:", in_vlan
	
		for out_vlan in VLANS:
			if (out_vlan == in_vlan): continue
			if VERBOSE > 5: print "OUT:", out_vlan
			if VERBOSE > 2:	sys.stdout.write('o')
	
			pkt_out = pkt
			pkt_out[Dot1Q].vlan = out_vlan

			# Finally send the packet
			sendp(pkt_out,verbose=False, iface=OWN_IF)

	 	# Give some feedback	
		#if VERBOSE > 2: print "BC => MC # ",pkt_out[IP].src,":",pkt_out[UDP].dport
		#if VERBOSE > 5: pkt_out.show() 

		sys.stdout.flush()
		return

# Setup the filter and start the handler
print "Ready for work."
sniff(prn=bridge_callback, filter=PACKET_FILTER, store=0, iface=OWN_IF)
