import os
import sys

from scapy.all import *
from scapy.layers.inet import IP, Ether, TCP, UDP
from scapy.layers.sctp import SCTP
import json

# file = open("udp.txt", "r+") # For UDP Packet
file = open("tcp.txt", "r+") # For TCP Packet
# file = open("sctp.txt", "r+") # For SCTP Packet
packet_dict = {}

meta_details = {
	"Meta":{
		"start":16,
		"end":24
	},
}
packet_details = {
	"Ether": {
		"start": 33,
		"end": 47,
		"type": {
			"0x800": {
				"start": 47,
				"end": 67,
				"proto": {
					"0x6": {
						"start": 67,
						"end": 87
					},
					"0x11": {
						"start": 67,
						"end": 75
					},
					"0x84": {
						"start": 67,
						"end": 79
					}
				}
			}
		}
	}
}

def pkt_to_json(json_pkt, pkt):
	for line in pkt.show(dump=True).split('\n'):
		if '###' in line:
			layer = line.strip('#[] ')
			packet_dict[layer] = {}
		elif '=' in line:
			key, val = line.split('=', 1)
			if((key.strip() == "type") or (key.strip() == "proto") or (key.strip() == "sport") or (key.strip() == "dport")):
				packet_dict[layer][key.strip()] = hex(Packet.getfieldval(pkt, key.strip()))
			else:
				packet_dict[layer][key.strip()] = val.strip()

def create_pkt(pkt_str, type="Ether"):
	for i in range(0, len(pkt_str)): 
		pkt_str[i] = int(pkt_str[i],16)

	packet = bytes(pkt_str)

	if(type == "Ether"):
		return Ether(raw(packet))
	elif(type == "0x800"):
		return IP(raw(packet))
	elif(type == "0x6"):
		return TCP(raw(packet))
	elif(type == "0x11"):
		return UDP(raw(packet))
	elif(type == "0x84"):
		return SCTP(raw(packet))
	else:
		return None

def parse_meta(li):
	for key in meta_details:
		pkt_str = li[meta_details[key]["start"]:meta_details[key]["end"]]
		for i in range(0, len(pkt_str)): 
			pkt_str[i] = int(pkt_str[i],16)
			if(i==(len(pkt_str)-1)):
				packet_dict["Meta"] = {}
				csum_offload = ((pkt_str[i] & 0xf0) >> 4)
				packet_dict["Meta"]["l3_outer_csum"] = 1 if((csum_offload & 0x1) >> 0) else 0
				packet_dict["Meta"]["l4_outer_csum"] = 1 if((csum_offload & 0x2) >> 1) else 0
				packet_dict["Meta"]["l3_inner_csum"] = 1 if((csum_offload & 0x4) >> 2) else 0
				packet_dict["Meta"]["l4_inner_csum"] = 1 if((csum_offload & 0x8) >> 3) else 0

def parse_packet(li):
	for key in packet_details:

		pkt_str = li[packet_details[key]["start"]:packet_details[key]["end"]]
		eth = create_pkt(pkt_str,"Ether")
		pkt_to_json(packet_dict,eth)

		for eth_type in packet_details[key]["type"]:

			if(eth_type ==  str(hex(eth.type))):
				pkt_str = li[packet_details[key]["type"][eth_type]["start"]:packet_details[key]["type"][eth_type]["end"]]
				ip = create_pkt(pkt_str,eth_type)
				pkt_to_json(packet_dict,ip)
				
				for proto in packet_details[key]["type"][eth_type]["proto"]:
					if(proto ==  str(hex(ip.proto))):
						pkt_str = li[packet_details[key]["type"][eth_type]["proto"][proto]["start"]:packet_details[key]["type"][eth_type]["proto"][proto]["end"]]
						ip_sub = create_pkt(pkt_str,proto)
						pkt_to_json(packet_dict,ip_sub)

	

packets = file.readlines()
input_packet = packets[0]
output_packet = packets[1]

new_input_packet = input_packet.replace('INPUT="', '')
new_input_packet = new_input_packet.replace(' "\n', '')
new_input_packet = new_input_packet.replace(' "\n', '')

li = list(new_input_packet.split(" "))
parse_meta(li)
parse_packet(li)

print(json.dumps(packet_dict))


email_file = open("email.txt","w+")
ip_proto = packet_dict['IP']['proto']
print("The IP proto is ", ip_proto)


if ip_proto == '0x11':
	ip_csum_result = packet_dict['IP']['chksum']
	print("The calculated value of ip_csum is", ip_csum_result)
	if ip_csum_result == '0xa3d6':
		email_file.write("The IP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The IP checksum calculation result DID NOT pass on Tx side\n")

	udp_csum_result = packet_dict['UDP']['chksum']
	print("The calculated value of udp_csum is", udp_csum_result)
	if udp_csum_result == '0xa8be':
		email_file.write("The UDP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The UDP checksum calculation result DID NOT pass on Tx side\n")

elif ip_proto == '0x6':
	ip_csum_result = packet_dict['IP']['chksum']
	print("The calculated value of ip_csum is", ip_csum_result)
	if ip_csum_result == '0xa3d5':
		email_file.write("The IP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The IP checksum calculation result DID NOT pass on Tx side\n")

	tcp_csum_result = packet_dict['TCP']['chksum']
	print("The calculated value of tcp_csum is", tcp_csum_result)
	if tcp_csum_result == '0x3b49':
		email_file.write("The TCP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The TCP checksum calculation result DID NOT pass on Tx side\n")


elif ip_proto == '0x84':
	ip_csum_result = packet_dict['IP']['chksum']
	print("The calculated value of ip_csum is", ip_csum_result)
	if ip_csum_result == '0xa35f':
		email_file.write("The IP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The IP checksum calculation result DID NOT pass on Tx side\n")

	sctp_csum_result = packet_dict['SCTP']['chksum']
	print("The calculated value of sctp_csum is", sctp_csum_result)
	if sctp_csum_result == '0x9e06eb83':
		email_file.write("The SCTP checksum calculation result passed on Tx side\n")
	else:
		email_file.write("The SCTP checksum calculation result DID NOT pass on Tx side\n")


file.close()
