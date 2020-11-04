from struct import unpack
import socket


DNS_PORT = 53
AAAA_TYPE = 28
A_TYPE = 1
NS_TYPE = 2


class DNS_parser:

	def get_compressed_num(self, first_byte, second_byte):
		return ((first_byte & 0x3f) << 8) + second_byte

	def is_compressed(self, num):
		return num & 0xc0 != 0

	def get_name(self, b, start_pos):
		if self.is_compressed(b[start_pos]):
			link = self.get_compressed_num(b[start_pos], b[start_pos + 1])
			name, _ = self.get_name(b, link)
			return name, start_pos + 2
		else:
			return self.get_name_from_labels(b, start_pos)

	def get_name_from_labels(self, b, start_pos):
		result = ''
		while True:
			if self.is_compressed(b[start_pos]):
				name, pos = self.get_name(b, start_pos)
				return result + name, pos

			section_len = b[start_pos]
			if section_len == 0:
				break
			start_pos += 1
			qname = b[start_pos: start_pos + section_len]
			result += qname.decode("ascii") + "."
			start_pos += section_len

		return result, start_pos + 1

	def get_queries(self, bytes_arr, start_pos, qdcount):
		result = []

		while qdcount > 0:
			qname, position = self.get_name(bytes_arr, start_pos)
			qtype, qclass = unpack("!HH", bytes_arr[position: position + 4])
			result.append({"QNAME": qname, "QTYPE": qtype, "QCLASS": qclass})
			qdcount -= 1
			start_pos = position + 4

		return result, start_pos


	def get_answers(self, bytes_arr, start_pos, ancount):
		result = []

		while ancount > 0:
			name, position = self.get_name(bytes_arr, start_pos)
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


	def get_server_name(self, data, dns_packet):
		start_pos = 0
		result = ''
		while start_pos < len(data):
			if self.is_compressed(data[start_pos]):
				position = self.get_compressed_num(data[start_pos], data[start_pos + 1])
				name, _ = self.get_name(dns_packet, position)
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

	def parse(self, packet):
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
		queries, position = self.get_queries(packet, start_pos, qdcount)
		answers, position = self.get_answers(packet, position, ancount)
		auth_servers, position = self.get_answers(packet, position, nscount)

		for answer in answers:
			if answer["TYPE"] == A_TYPE:
				answer["DATA"] = socket.inet_ntoa(answer["DATA"])

		for server in auth_servers:
			server["DATA"] = self.get_server_name(server["DATA"], packet)

		return {"queries": queries, "answers": answers, "auth_servers": auth_servers}
