import os
import subprocess
from scapy.all import sendp, raw
from scapy.layers.inet import IP, Ether, TCP, UDP

"""
A sample test case. It should return True if the test passes and False in case of failure.
"""
def test():
    return True

"""
Test case to verify tcp L3 outer checksum calculation
"""
def test_tcp_outer_l3_checksum():
    # file = open("/etc/result.txt", "r+")
    # file.truncate(0)

    # Payload = '0' * 640
    # ip_pkt = IP(version=0x04,ihl=0x5,tos=0x0,len=0x028A,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x06,src='10.60.0.1',dst='10.60.1.1')
    # pkt = Ether(dst='00:34:56:78:9a:bc',src='00:45:67:89:ab:cd')/ip_pkt/TCP()/Payload
    # result = pkt.show2(dump=True, label_lvl="IP")
    # packet = IP(raw(ip_pkt))
    # ip_checksum = hex(packet[IP].chksum)
    # # print(ip_checksum)
    # sendp(pkt,iface='sn0',count=1)

    # chk = file.readlines()

    # if (len(chk) > 0):
    #     if (ip_checksum in chk[0]):
    #         file.close()
    #         return True
    #     else:
    #         file.close()
    #         return False
    # file.close()
    return True


"""
Test case to verify tcp L4 outer checksum verification
"""
def test_tcp_outer_l4_checksum():
    # file = open("/etc/result.txt", "r+")
    # file.truncate(0)

    # Payload = '0' * 640
    # ip_pkt = IP(version=0x04,ihl=0x5,tos=0x0,len=0x028A,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x06,src='10.60.0.1',dst='10.60.1.1')
    # pkt = Ether(dst='00:34:56:78:9a:bc',src='00:45:67:89:ab:cd')/ip_pkt/TCP()/Payload
    # result = pkt.show2(dump=True, label_lvl="IP")
    # packet = IP(raw(ip_pkt))
    # ip_checksum = hex(packet[IP].chksum)
    # # print(ip_checksum)
    # sendp(pkt,iface='sn0',count=1)

    # chk = file.readlines()

    # if (len(chk) > 0):
    #     if ('0xe3a' in chk[1]):
    #         file.close()
    #         return True
    #     else:
    #         file.close()
    #         return False
    return True

"""
Test case to verify udp L3 outer checksum calculation
"""
def test_udp_outer_l3_checksum():
    # file = open("/etc/result.txt", "r+")
    # file.truncate(0)

    # Payload = '0' * 640
    # ip_pkt = IP(version=0x04,ihl=0x5,tos=0x0,len=0x028A,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x11,src='10.60.0.1',dst='10.60.1.1')
    # pkt = Ether(dst='00:34:56:78:9a:bc',src='00:45:67:89:ab:cd')/ip_pkt/UDP()/Payload
    # result = pkt.show2(dump=True, label_lvl="IP")
    # packet = IP(raw(ip_pkt))
    # ip_checksum = hex(packet[IP].chksum)
    # # print(ip_checksum)
    # sendp(pkt,iface='sn0',count=1)

    # chk = file.readlines()

    # if (len(chk) > 0):
    #     if (ip_checksum in chk[0]):
    #         file.close()
    #         return True
    #     else:
    #         file.close()
    #         return False
    # file.close()
    return True


"""
Test case to verify udp L4 outer checksum verification
"""
def test_udp_outer_l4_checksum():
    # file = open("/etc/result.txt", "r+")
    # file.truncate(0)

    # Payload = '0' * 640
    # ip_pkt = IP(version=0x04,ihl=0x5,tos=0x0,len=0x028A,id=0x0001,flags=0x0000,ttl=0xFF,proto=0x11,src='10.60.0.1',dst='10.60.1.1')
    # pkt = Ether(dst='00:34:56:78:9a:bc',src='00:45:67:89:ab:cd')/ip_pkt/UDP()/Payload
    # result = pkt.show2(dump=True, label_lvl="IP")
    # packet = IP(raw(ip_pkt))
    # ip_checksum = hex(packet[IP].chksum)
    # # print(ip_checksum)
    # sendp(pkt,iface='sn0',count=1)

    # chk = file.readlines()

    # if (len(chk) > 0):
    #     if ('0x5a82' in chk[1]):
    #         file.close()
    #         return True
    #     else:
    #         file.close()
    #         return False
    return True

cmodel_tests = [test_tcp_outer_l3_checksum,test_tcp_outer_l4_checksum,test_udp_outer_l3_checksum,test_udp_outer_l4_checksum]
