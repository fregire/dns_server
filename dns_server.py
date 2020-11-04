import socket
from dnslib import *
from struct import unpack
import threading
from dns_parser import DNS_parser

ROOT_IP = "198.41.0.4"
DNS_PORT = 53
AAAA_TYPE = 28
A_TYPE = 1
NS_TYPE = 2


class DNS_server:
	def __init__(self, root_ip, parser, buffer_size=65536):
		self.root_ip = root_ip
		self.buffer_size = buffer_size
		self.parser = parser


	def start(self, host="0.0.0.0", port=0):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind((host, port))
		while True:
			client_request, _ = s.recvfrom(self.buffer_size)
			dns_packet = self.parser.parse(client_request)
			url = dns_packet["queries"][0]["QNAME"]
			ip = self.get_ip(url, self.root_ip, set())


	def get_response(self, url, server):
		packet = DNSRecord(q=DNSQuestion(url)).pack()
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.sendto(bytes(packet), (server, DNS_PORT))

		data = s.recvfrom(1024)
		if not data:
			return None

		return self.parser.parse(data[0])

	def get_ip(self, url, server, visited_urls):
		dns_response = self.get_response(url, server)
		auth_servers = []

		if dns_response["answers"]:
			for response in dns_response["answers"]:
				if response["TYPE"] == A_TYPE:
					return response["DATA"]
			return dns_response["answers"]
		else:
			for server in dns_response["auth_servers"]:
				server_url = server["DATA"]
				if server_url in visited_urls:
					continue
				else:
					visited_urls.add(server_url)
					ip = self.get_ip(url, server_url, visited_urls)
					if ip:
						return ip



def main():
	server = DNS_server(ROOT_IP, DNS_parser())
	server.start("127.0.0.1", DNS_PORT)

if __name__ == "__main__":
	main()
