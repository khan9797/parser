from scapy.all import Packet, raw
from scapy.layers.inet import IP, Ether, TCP, UDP
from scapy.layers.l2   import Dot1Q
from scapy.layers.sctp import SCTP

payload = '0' * 640

ether_hdr = Ether(src='00:34:56:78:9a:bc',dst='00:45:67:89:ab:cd')
ip_hdr = IP(version=0x04,ihl=0x5,tos=0x0,id=0x0001,flags=0x0000,ttl=0x64,src='10.60.0.1',dst='10.60.1.1')
tcp_hdr = TCP(sport=4250, dport=4300)
udp_hdr = UDP(sport=4250, dport=4300)
sctp_hdr = SCTP(sport=4250, dport=4300)
vlan_header = Dot1Q(vlan=5)