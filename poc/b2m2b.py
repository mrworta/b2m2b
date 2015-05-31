#! /usr/bin/env python
# 
# BroadCast to MultiCast to BroadCast PoC
# v0.1 / MrWorta
# - Requires tcpdump and python-scapy
# - No error handling yet
# - Tested with Cisco PIM/IGMP and CS 1.6
#
import socket, struct
from scapy.all import *

# Do some init stuff
VERBOSE = 0

OWN_IF = "eth0"
MCAST_GRP = "239.66.66.66"
BCAST_MAC = "ff:ff:ff:ff:ff:ff"

# The first part about ip and bc/mc is mandatory. Ports can be customized.
PACKET_FILTER = "ip and (broadcast or multicast) and dst portrange 1024-65535"

# Fetch own MAC
# $ToDo: Take care of multiple interfaces.
OWN_MACS = get_if_hwaddr(OWN_IF) 

def bridge_callback(pkt):
	
	# For now, ignore my packets after sniff. (Debug)
	# $ToDo: change to pcap filter for better performance
	try:
		OWN_MACS.index(pkt[Ether].src)
		return 
	except ValueError:
		pass
	###

	# Handle MultiCast Packets to our group
	# Transform MC to BroadCast
	if (pkt[IP].dst == MCAST_GRP): 	

		# Construct new packet
		pkt_out = Ether()/IP()/UDP()
		pkt_out[Ether].dst = BCAST_MAC
		pkt_out[Ether].src = OWN_MACS

		# Spoof source of original packet / dst=broadcast
		pkt_out[IP].src = pkt[IP].src
		pkt_out[IP].dst = "255.255.255.255"
		#
		# Copy payload
		pkt_out[UDP] = pkt[UDP]

	 	# Give some feedback	
		if VERBOSE > 2: print "MC => BC # ",pkt_out[IP].src,":",pkt_out[UDP].dport
		if VERBOSE > 5: pkt_out.show() 

		# Finally send the packet
		sendp(pkt_out,verbose=False, iface=OWN_IF)

		return

	# Handle all broadcast packets
	# Transform BC to MultiCast:
	if (pkt[Ether].dst == BCAST_MAC): 	

		# Construct new packet
		pkt_out = Ether()/IP()/UDP()
		pkt_out[Ether].src = OWN_MACS

		# Spoof source of original packet
		pkt_out[IP].src = pkt[IP].src

		# $ToDo: Does the library calculate the MC destination MAC??
		#
		pkt_out[IP].dst = MCAST_GRP
		pkt_out[UDP] = pkt[UDP]

	 	# Give some feedback	
		if VERBOSE > 2: print "BC => MC # ",pkt_out[IP].src,":",pkt_out[UDP].dport
		if VERBOSE > 5: pkt_out.show() 

		# Finally send the packet
		sendp(pkt_out,verbose=False, iface=OWN_IF)

		return

# Join MC Group:
print "Joining multicast group..."
try:
	mc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	mc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	greq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
	mc_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, greq)
except:
	print "Error joining group. Do you have mCast Route?"
	exit


# Setup the filter and start the handler
print "Ready for work."
sniff(prn=bridge_callback, filter=PACKET_FILTER, store=0, iface=OWN_IF)
