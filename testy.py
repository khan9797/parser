import os
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import Ether
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP


print("Hello")
test_type = [0,1] #0 => TCP, 1 => UDP
#a = IP(src="10.60.0.1", dst="10.60.1.1", version="4L", ihl=0x45, tos=0x0, len=0x0020, id=0x0001, flags=0x0000, ttl=0x40, proto=0x96)
#pkt_ip4 = IP(version=0x04,ihl=0x5,tos=0x0,len=0x0014,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x00,src='10.60.0.1',dst='10.60.1.1')
#scapy.hexdump(pkt_ip4)
#len=0x2a8,
Payload = '0' * 640
#ip_pktin = IP(version=0x04,ihl=0x5,tos=0x0,id=0x0001,len=0x294,flags=0x0000,ttl=0x40,proto=0x96,src='10.60.10.10',dst='10.60.10.11')
ip_pktout = IP(version=0x04,ihl=0x5,tos=0x0,id=0x0001,flags=0x0000,ttl=0x,proto=0x96,src='10.60.0.1',dst='10.60.1.1')
pkt = Ether(src='00:34:56:78:9a:bc',dst='00:45:67:89:ab:cd')/ip_pktout/Payload
sendp(pkt,iface='sn0',count=1)
print(pkt.show2())
# 0x00, 0x34, 0x56, 0x78, 0x9A, 0xBC       //sn0   PF0
# 0x00, 0x45, 0x67, 0x89, 0xAB, 0xCD      //sn1  PF1
# print
result = pkt.show2(dump=True, label_lvl="IP")
packet1 = IP(raw(ip_pktin))
packet2 = IP(raw(ip_pktout))
ip_checksum1 = hex(packet1[IP].chksum)
ip_checksum2 = hex(packet2[IP].chksum)
print(ip_checksum1)
print(ip_checksum2)

#
# file1 = open("jenkins.txt", "w+")
#
#
#
#
# for i in test_type:
#     if i == 0:
#         file = open("/etc/result.txt", "r+")
#         file.truncate(0)
#
#         ip_pkt = IP(version=0x04,ihl=0x5,tos=0x0,len=0x028A,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x06,src='10.60.0.1',dst='10.60.1.1')
#         pkt = Ether(dst='00:34:56:78:9a:bc',src='00:45:67:89:ab:cd')/ip_pkt/TCP()/Payload
#         result = pkt.show2(dump=True, label_lvl="IP")
#         packet = IP(raw(ip_pkt))
#         ip_checksum = hex(packet[IP].chksum)
#         print(ip_checksum)
#         sendp(pkt,iface='sn0',count=1)
#         # recieved = scapy.sr(
#         # Ether(dst='00:34:56:78:9a:bc',src='00:45:67:89:ab:cd')/
#         # IP(version=0x04,ihl=0x5,tos=0x0,len=0x028A,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x06,src='10.60.0.1',dst='10.60.1.1')/
#         # TCP()/Payload
#         # )
#         # print(recieved.show())
#
#         chk = file.readlines();
#         print(len(chk))
#         print(chk)
#         if (len(chk) > 0):
#             if (ip_checksum in chk[0]):
#                 print("The L3 outer checksum calculated successfully")
#                 file1.write(chk[0])
#             else:
#                 print("The L3 outer checksum failed")
#                 file1.write("The L3 outer checksum failed")
#
#             if ('0xe3a' in chk[1]):
#                 print("The L4 outer checksum calculated successfully")
#                 file1.write(chk[1])
#             else:
#                 print("The L4 outer checksum failed")
#                 file1.write("The L4 outer checksum failed")
#         file.close()
#
#
#     if i == 1:
#
#         file = open("/etc/result.txt", "r+")
#         file.truncate(0)
#
#         sendp(
#             Ether(dst='00:34:56:78:9a:bc',src='00:45:67:89:ab:cd')/
#             IP(version=0x04,ihl=0x5,tos=0x0,len=0x028A,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x11,src='10.60.0.1',dst='10.60.1.1')/
#             UDP()/Payload,iface='sn0',count=1
#             )
#
#         chk = file.readlines();
#         print(len(chk))
#         print(chk)
#         if (len(chk) > 0):
#             if ('0xa3e8' in chk[0]):
#                 print("The L3 outer checksum calculated successfully")
#                 file1.write(chk[0])
#             else:
#                 print("The L3 outer checksum failed")
#                 file1.write("The L3 outer checksum failed")
#
#             if ('0x5a82' in chk[1]):
#                 print("The L4 outer checksum calculated successfully")
#                 file1.write(chk[1])
#             else:
#                 print("The L4 outer checksum failed")
#                 file1.write("The L4 outer checksum failed")
#         file.close()
# file1.close()
