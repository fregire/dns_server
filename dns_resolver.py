import socket
from dnslib import *
from struct import unpack


ROOT_IP = "198.41.0.4"
DNS_PORT = 53
AAAA_TYPE = 28
A_TYPE = 1
NS_TYPE = 2

def get_compressed_num(first_byte, second_byte):
	return ((first_byte & 0x3f) << 8) + second_byte

def is_compressed(num):
	return num & 0xc0 != 0

def get_name(b, start_pos):
	if is_compressed(b[start_pos]):
		link = get_compressed_num(b[start_pos], b[start_pos + 1])
		name, _ = get_name(b, link)
		return name, start_pos + 2
	else:
		return get_name_from_labels(b, start_pos)

def get_name_from_labels(b, start_pos):
	result = ''
	while True:
		if is_compressed(b[start_pos]):
			name, pos = get_name(b, start_pos)
			return result + name, pos

		section_len = b[start_pos]
		if section_len == 0:
			break
		start_pos += 1
		qname = b[start_pos: start_pos + section_len]
		result += qname.decode("ascii") + "."
		start_pos += section_len

	return result, start_pos + 1

def get_queries(bytes_arr, start_pos, qdcount):
	result = []

	while qdcount > 0:
		qname, position = get_name(bytes_arr, start_pos)
		qtype, qclass = unpack("!HH", bytes_arr[position: position + 4])
		result.append({"QNAME": qname, "QTYPE": qtype, "QCLASS": qclass})
		qdcount -= 1
		start_pos = position + 4

	return result, start_pos


def get_answers(bytes_arr, start_pos, ancount):
	result = []

	while ancount > 0:
		name, position = get_name(bytes_arr, start_pos)
		_type, _class, ttl, rd_len = unpack("!HHIH", bytes_arr[position: position + 10])
		start_pos = position + 10
		rdata = bytes_arr[start_pos: start_pos + rd_len]
		start_pos += rd_len
		result.append({
			"NAME": name, 
			"TYPE": _type, 
			"CLASS": _class,
			"TTL": ttl, 
			"LEN": rd_len, 
			"DATA": rdata
		})
		ancount -= 1

	return result, start_pos


def get_server_name(data, dns_packet):
	start_pos = 0
	result = ''
	while start_pos < len(data):
		if is_compressed(data[start_pos]):
			position = get_compressed_num(data[start_pos], data[start_pos + 1])
			name, _ = get_name(dns_packet, position)
			result += name
			start_pos += 2
		else:
			length = data[start_pos]
			#Завершающая метка
			if length == 0:
				break
			start_pos += 1
			name = data[start_pos: start_pos + length].decode("ascii") + "."
			result += name
			start_pos += length

	return result

def parse_dns_packet(packet):
	start_pos = 0
	header = unpack("!HHHHHH", packet[:12])
	start_pos = 12
	packet_id = header[0]
	flags = header[1]
	qdcount = header[2]
	ancount = header[3]
	nscount = header[4]
	arcount = header[5]

	#reading requests
	queries, position = get_queries(packet, start_pos, qdcount)
	answers, position = get_answers(packet, position, ancount)
	auth_servers, position = get_answers(packet, position, nscount)

	for answer in answers:
		if answer["TYPE"] == A_TYPE:
			answer["DATA"] = socket.inet_ntoa(answer["DATA"])

	for server in auth_servers:
		server["DATA"] = get_server_name(server["DATA"], packet)

	return {"queries": queries, "answers": answers, "auth_servers": auth_servers}


def get_repsonse(url, server_ip):
	packet = DNSRecord(q=DNSQuestion(url)).pack()
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.sendto(bytes(packet), (server_ip, DNS_PORT))

	data = s.recvfrom(1024)
	if not data:
		return None

	return parse_dns_packet(data[0])


def get_ip(url, server, visited_urls):
	dns_response = get_repsonse(url, server)
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
				ip = get_ip(url, server_url, visited_urls)
				if ip:
					return ip

	return None

def main():
	print(get_ip("ya.ru", ROOT_IP, set()))


if __name__ == "__main__":
	main()