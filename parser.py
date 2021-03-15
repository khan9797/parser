import os
import sys
from Parser.Parser import Parser
import json

# file = open("udp.txt", "r+") # For UDP Packet
file = open("tcp.txt", "r+") # For TCP Packet
# file = open("sctp.txt", "r+") # For SCTP Packet

meta_details = {}
packet_details = {}

with open('config/meta_details.json') as f:
  meta_details = json.load(f)


with open('config/packet_details.json') as f:
  packet_details = json.load(f)

packets = file.readlines()
input_packet = packets[0]
output_packet = packets[1]

new_input_packet = input_packet.replace('INPUT="', '')
new_input_packet = new_input_packet.replace(' "\n', '')
new_input_packet = new_input_packet.replace(' "\n', '')

li = list(new_input_packet.split(" "))

parser = Parser()
parser.parse_meta(li,meta_details)
parser.parse_packet(li, packet_details)

print(json.dumps(parser.packet_dict))


email_file = open("email.txt","w+")
ip_proto = parser.packet_dict['IP']['proto']
print("The IP proto is ", ip_proto)


if ip_proto == '0x11':
	ip_csum_result = parser.packet_dict['IP']['chksum']
	print("The calculated value of ip_csum is", ip_csum_result)
	if ip_csum_result == '0xa3d6':
		email_file.write("The IP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The IP checksum calculation result DID NOT pass on Tx side\n")

	udp_csum_result = parser.packet_dict['UDP']['chksum']
	print("The calculated value of udp_csum is", udp_csum_result)
	if udp_csum_result == '0xa8be':
		email_file.write("The UDP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The UDP checksum calculation result DID NOT pass on Tx side\n")

elif ip_proto == '0x6':
	ip_csum_result = parser.packet_dict['IP']['chksum']
	print("The calculated value of ip_csum is", ip_csum_result)
	if ip_csum_result == '0xa3d5':
		email_file.write("The IP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The IP checksum calculation result DID NOT pass on Tx side\n")

	tcp_csum_result = parser.packet_dict['TCP']['chksum']
	print("The calculated value of tcp_csum is", tcp_csum_result)
	if tcp_csum_result == '0x3b49':
		email_file.write("The TCP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The TCP checksum calculation result DID NOT pass on Tx side\n")


elif ip_proto == '0x84':
	ip_csum_result = parser.packet_dict['IP']['chksum']
	print("The calculated value of ip_csum is", ip_csum_result)
	if ip_csum_result == '0xa35f':
		email_file.write("The IP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The IP checksum calculation result DID NOT pass on Tx side\n")

	sctp_csum_result = parser.packet_dict['SCTP']['chksum']
	print("The calculated value of sctp_csum is", sctp_csum_result)
	if sctp_csum_result == '0x9e06eb83':
		email_file.write("The SCTP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The SCTP checksum calculation result DID NOT pass on Tx side\n")


file.close()
