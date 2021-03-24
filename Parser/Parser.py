from scapy.all import Packet, raw
from scapy.layers.inet import IP, Ether, TCP, UDP
from scapy.layers.l2   import Dot1Q
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

#creating packets using Scapy parser from hex string
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
        elif(type == "vlan"):
            return Dot1Q(raw(packet))
        else:
            return None

    def parse_meta(self, li, meta_details, pkt_type):
        for key in meta_details:
            self.packet_dict["Meta"] = {}
            for meta in meta_details[key]:
                if((pkt_type == meta) and pkt_type =="RX"):
                    pkt_str = li[meta_details[key]["RX"]["start"]:meta_details[key]["RX"]["end"]]
                    for i in range(0, len(pkt_str)): 
                        pkt_str[i] = int(pkt_str[i],16)
                        
                    for i in range(0, len(pkt_str)):
                        if(i == 0 ):
                            csum_offload = ((pkt_str[i] & 0xf0) >> 4)
                            self.packet_dict["Meta"]["l3_outer_csum"] = 1 if((csum_offload & 0x1) >> 0) else 0
                            self.packet_dict["Meta"]["l4_outer_csum"] = 1 if((csum_offload & 0x2) >> 1) else 0
                            self.packet_dict["Meta"]["l3_inner_csum"] = 1 if((csum_offload & 0x4) >> 2) else 0
                            self.packet_dict["Meta"]["l4_inner_csum"] = 1 if((csum_offload & 0x8) >> 3) else 0

                            tunnel_packet = ((pkt_str[i] & 0x0f))
                            self.packet_dict["Meta"]["tunnel_packet"] = 1 if((tunnel_packet & 0x8) >> 3) else 0
                        elif(i == 1 ):
                            rss_hash_type = pkt_str[i]
                            if(rss_hash_type):
                                self.packet_dict["Meta"]["rss_hash_type"] = {}
                                self.packet_dict["Meta"]["rss_hash_type"]["l3_src"] = ((rss_hash_type & 0x03) >> 0)
                                self.packet_dict["Meta"]["rss_hash_type"]["l3_dst"] = ((rss_hash_type & 0x0c) >> 2)
                                self.packet_dict["Meta"]["rss_hash_type"]["l4_src"] = ((rss_hash_type & 0x30) >> 4)
                                self.packet_dict["Meta"]["rss_hash_type"]["l4_dst"] = ((rss_hash_type & 0xc0) >> 6)
                            else:
                                self.packet_dict["Meta"]["rss_hash_type"] = rss_hash_type
                        elif(i == 2 ):
                            rss_hash = pkt_str[i:i+4]
                            rss_hash.reverse()
                            hash_str = ''.join([(hex(i).replace('0x','')) for i in rss_hash])
                            self.packet_dict["Meta"]["rss_hash"] = '0x'+hash_str
                            i += 4
                        elif(i == 6 ):
                            self.packet_dict["Meta"]["vlan_fields"] = {}
                            vlan_fields = pkt_str[i:i+2]
                            vlan_fields.reverse()
                            vlan_str = ''.join([(hex(i).replace('0x','')) for i in vlan_fields])
                            self.packet_dict["Meta"]["vlan_fields"]['vlan_tag']     = hex((int(vlan_str,16) & 0xfff0) >> 4)
                            self.packet_dict["Meta"]["vlan_fields"]['vlan_id']      = hex((int(vlan_str,16) & 0xe) >> 1)
                            self.packet_dict["Meta"]["vlan_fields"]['vlan_present'] = ((int(vlan_str,16) & 0x1) >> 0)
                            i += 2
                elif((pkt_type == meta) and pkt_type == "TX"):
                    pkt_str = li[meta_details[key]["TX"]["start"]:meta_details[key]["TX"]["end"]]
                    pkt_str = pkt_str[-3:]
                    print(pkt_str)

                    for i in range(0, len(pkt_str)): 
                        pkt_str[i] = int(pkt_str[i],16)

                    for i in range(0, len(pkt_str)):
                        if(i == 0):
                            csum_offload = ((pkt_str[i] & 0xf0) >> 4)
                            self.packet_dict["Meta"]["l3_outer_csum"] = 1 if((csum_offload & 0x1) >> 0) else 0
                            self.packet_dict["Meta"]["l4_outer_csum"] = 1 if((csum_offload & 0x2) >> 1) else 0
                            self.packet_dict["Meta"]["l3_inner_csum"] = 1 if((csum_offload & 0x4) >> 2) else 0
                            self.packet_dict["Meta"]["l4_inner_csum"] = 1 if((csum_offload & 0x8) >> 3) else 0
                            vlan_tag = pkt_str[i:i+2]
                            vlan_str = ''.join([f"{j:02x}" for j in vlan_tag])
                            self.packet_dict["Meta"]['vlan_tag']     = hex((int(vlan_str,16) & 0x0fff))
                            i += 2
                        elif(i==2):
                            vlan = pkt_str[i]

                            self.packet_dict["Meta"]["insert_vlan"] =   1 if((vlan & 0x80) >> 7) else 0
                            self.packet_dict["Meta"]["vlan_priority"] = (vlan & 0x70) >> 4

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