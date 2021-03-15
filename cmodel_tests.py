import os
import subprocess
from scapy.all import sendp, raw
from scapy.layers.inet import IP, Ether, TCP, UDP
import json
from Parser.Parser import Parser

meta_details = {}
packet_details = {}

with open('config/meta_details.json') as f:
  meta_details = json.load(f)


with open('config/packet_details.json') as f:
  packet_details = json.load(f)

"""
A sample test case. It should return True if the test passes and False in case of failure.
"""
def test():
    return True

"""
Test case to verify tcp L3 outer checksum calculation
"""
def test_tcp_outer_l3_checksum():
    file = open("tcp.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)

    if(parser.packet_dict['IP']['chksum'] == "0xa3d5"):
        return True
    else:
        return False

"""
Test case to verify tcp L4 outer checksum verification
"""
def test_tcp_outer_l4_checksum():
    file = open("tcp.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)
    
    if(parser.packet_dict['TCP']['chksum'] == "0x3b49"):
        return True
    else:
        return False

"""
Test case to verify udp L3 outer checksum calculation
"""
def test_udp_outer_l3_checksum():
    file = open("udp.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)

    if(parser.packet_dict['IP']['chksum'] == "0xa3d6"):
        return True
    else:
        return False


"""
Test case to verify udp L4 outer checksum verification
"""
def test_udp_outer_l4_checksum():
    file = open("udp.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)
    
    if(parser.packet_dict['UDP']['chksum'] == "0xa8be"):
        return True
    else:
        return False

cmodel_tests = [test_tcp_outer_l3_checksum,test_tcp_outer_l4_checksum,test_udp_outer_l3_checksum,test_udp_outer_l4_checksum]
