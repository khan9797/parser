import os
import subprocess
from scapy.all import *
#from scapy.layers.inet import IP, Ether, TCP, UDP
import json
from Parser.Parser import Parser
from packets import *

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
def test_tcp_outer_l3_checksum_calculation():
    # TODO: Create and send the packet here
    packet = ip_hdr/TCP()/payload
    packet.show()
    #ip_packet = IP(raw(packet))  # Build packet (automatically done when sending)
    #packet = packet.__class__(bytes(packet))
    packet.show()
    ip_checksum = packet[IP].chksum
    tcp_checksum = packet[TCP].chksum
    print('The ip_csum is', ip_checksum)
    print('The tcp_csum is', tcp_checksum)

    file = open("tcp_tx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    # parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)

    if(parser.packet_dict['IP']['chksum'] == "0xa3d5"):
        return True
    else:
        return False

"""
Test case to verify tcp L4 outer checksum verification
"""
def test_tcp_outer_l4_checksum_calculation():
    # TODO: Create and send the packet here

    file = open("tcp_tx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    # parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)
    
    if(parser.packet_dict['TCP']['chksum'] == "0x3b49"):
        return True
    else:
        return False

"""
Test case to verify udp L3 outer checksum calculation
"""
def test_udp_outer_l3_checksum_calculation():
    # TODO: Create and send the packet here

    file = open("udp_tx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()

    # parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)

    if(parser.packet_dict['IP']['chksum'] == "0xa3d6"):
        return True
    else:
        return False

"""
Test case to verify udp L4 outer checksum verification
"""
def test_udp_outer_l4_checksum_calculation():
    # TODO: Create and send the packet here

    file = open("udp_tx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    # parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)
    
    if(parser.packet_dict['UDP']['chksum'] == "0xa8be"):
        return True
    else:
        return False

"""
Test case to verify sctp L3 outer checksum calculation
"""
def test_sctp_outer_l3_checksum_calculation():
    # TODO: Create and send the packet here

    file = open("sctp_tx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()

    # parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)

    if(parser.packet_dict['IP']['chksum'] == "0xa35f"):
        return True
    else:
        return False

"""
Test case to verify sctp L4 outer checksum verification
"""
def test_sctp_outer_l4_checksum_calculation():
    # TODO: Create and send the packet here

    file = open("sctp_tx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    # parser.parse_meta(li,meta_details)
    parser.parse_packet(li, packet_details)
    
    if(parser.packet_dict['SCTP']['chksum'] == "0x9e06eb83"):
        return True
    else:
        return False

"""
Test case to verify tcp L3 outer checksum verification
"""
def test_tcp_outer_l3_checksum_verification():
    # TODO: Create and send the packet here

    file = open("tcp_rx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    parser.parse_meta(li,meta_details, "RX")
    parser.parse_packet(li, packet_details)
    # print(json.dumps(parser.packet_dict))
    if(parser.packet_dict['Meta']['l3_outer_csum']):
        return True
    else:
        return False

"""
Test case to verify tcp L4 outer checksum verification
"""
def test_tcp_outer_l4_checksum_verification():
    # TODO: Create and send the packet here

    file = open("tcp_rx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    parser.parse_meta(li,meta_details, "RX")
    parser.parse_packet(li, packet_details)

    if(parser.packet_dict['Meta']['l4_outer_csum']):
        return True
    else:
        return False

"""
Test case to verify tcp L4 outer checksum verification
"""
def test_vlan():
    # TODO: Create and send the packet here

    file = open("vlan_tx.txt", "r+")
    packets = file.readlines()
    packets = packets[1]

    packet = packets.replace('OUTPUT="', '')
    packet = packet.replace(' "\n', '')

    li = list(packet.split(" "))
    parser = Parser()
    parser.parse_meta(li,meta_details, "TX")
    vlan_hdr = li[packet_details["Ether"]["start"]+12:packet_details["Ether"]["start"]+16]
    vlan_hdr = vlan_hdr[2:]+vlan_hdr[:2]
    li = li[:packet_details["Ether"]["start"]+12] + li[packet_details["Ether"]["start"]+16:]
    parser.parse_packet(li, packet_details)
    vlan_pkt = parser.create_pkt(vlan_hdr,"vlan")
    parser.pkt_to_json(parser.packet_dict,vlan_pkt)
    print(json.dumps(parser.packet_dict))
    # if(parser.packet_dict['Meta']['l4_outer_csum']):
    #     return True
    # else:
    #     return False

cmodel_tests = [
    test_tcp_outer_l3_checksum_calculation,
    test_tcp_outer_l4_checksum_calculation,
    test_tcp_outer_l3_checksum_verification,
    test_tcp_outer_l4_checksum_verification,
    test_udp_outer_l3_checksum_calculation,
    test_udp_outer_l4_checksum_calculation,
    test_sctp_outer_l3_checksum_calculation,
    test_sctp_outer_l4_checksum_calculation,
    test_vlan
]
