from scapy.all import Packet, raw
from scapy.layers.inet import IP, Ether, TCP, UDP
from scapy.layers.sctp import SCTP

class Parser:
    packet_dict = {}

    def pkt_to_json(self, json_pkt, pkt):
        for line in pkt.show(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('#[] ')
                self.packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                if((key.strip() == "type") or (key.strip() == "proto") or (key.strip() == "sport") or (key.strip() == "dport")):
                    self.packet_dict[layer][key.strip()] = hex(Packet.getfieldval(pkt, key.strip()))
                else:
                    self.packet_dict[layer][key.strip()] = val.strip()

    def create_pkt(self, pkt_str, type="Ether"):
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

    def parse_meta(self, li, meta_details):
        for key in meta_details:
            pkt_str = li[meta_details[key]["start"]:meta_details[key]["end"]]
            for i in range(0, len(pkt_str)): 
                pkt_str[i] = int(pkt_str[i],16)
                if(i==(0)):
                    self.packet_dict["Meta"] = {}
                    csum_offload = ((pkt_str[i] & 0xf0) >> 4)
                    self.packet_dict["Meta"]["l3_outer_csum"] = 1 if((csum_offload & 0x1) >> 0) else 0
                    self.packet_dict["Meta"]["l4_outer_csum"] = 1 if((csum_offload & 0x2) >> 1) else 0
                    self.packet_dict["Meta"]["l3_inner_csum"] = 1 if((csum_offload & 0x4) >> 2) else 0
                    self.packet_dict["Meta"]["l4_inner_csum"] = 1 if((csum_offload & 0x8) >> 3) else 0

    def parse_packet(self, li, packet_details):
        for key in packet_details:

            pkt_str = li[packet_details[key]["start"]:packet_details[key]["end"]]
            eth = self.create_pkt(pkt_str,"Ether")
            self.pkt_to_json(self.packet_dict,eth)

            for eth_type in packet_details[key]["type"]:

                if(eth_type ==  str(hex(eth.type))):
                    pkt_str = li[packet_details[key]["type"][eth_type]["start"]:packet_details[key]["type"][eth_type]["end"]]
                    ip = self.create_pkt(pkt_str,eth_type)
                    self.pkt_to_json(self.packet_dict,ip)
                    
                    for proto in packet_details[key]["type"][eth_type]["proto"]:
                        if(proto ==  str(hex(ip.proto))):
                            pkt_str = li[packet_details[key]["type"][eth_type]["proto"][proto]["start"]:packet_details[key]["type"][eth_type]["proto"][proto]["end"]]
                            ip_sub = self.create_pkt(pkt_str,proto)
                            self.pkt_to_json(self.packet_dict,ip_sub)