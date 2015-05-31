# b2m2b
A BroadCast to MultiCast - and vice versa - bridge.

Intended as a proof-of-concept for "briding" broadcast Services (eg. CounterStrike) across subnets using multicast.

#####

: How should it work?

B->M)
 - A broadcast packet is gets captured on the bc interface of the bridge. 
 - It is translated to a multicast packet and adressed to a specific mc group.
 - The source IP of the original bc is spoofed. 

M->B)
 - The bridge subscribes to a specific multicast group using IGMP.
 - A multicast packet it received and gets translated to broadcast. 
 - Again the original source IP is used (spoofed) to send the packet.

: Compile?

It should compile on nearly any \*nix if you provide libpcap.
Just 'make'.

: Run?

Yes. Run.
