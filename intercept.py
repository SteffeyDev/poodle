#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
from scapy.all import *

def client_to_server(packet):
	pkt = IP(packet.get_payload())
	print(pkt)
	print(pkt[0].summary())
	#print(pkt[TCP].payload)
	#packet.set_payload(str(pkt))
	packet.accept()

def server_to_client(packet):
	pkt = IP(packet.get_payload())
	print(pkt)
	print(pkt[0].summary())
	packet.accept()

nfqueue = NetfilterQueue()

# client to server intercept
nfqueue.bind(0, client_to_server)

# server to client intercept
nfqueue.bind(1, server_to_client)

try:
	nfqueue.run()
except KeyboardInterrupt:
	pass

nfqueue.unbind()
