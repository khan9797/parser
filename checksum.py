from scapy.all import *

payload = '0'*640

# Get the TCP checksum computed by Scapy
packet = IP()/TCP()/payload
# packet = IP(raw(packet))  # Build packet (automatically done when sending)
packet = packet.__class__(bytes(packet))
# print(packet.show())
checksum_scapy = packet[TCP].chksum
print(hex(checksum_scapy))

# Get the UDP checksum computed by Scapy
packet = IP()/UDP()/payload
# packet = IP(raw(packet))  # Build packet (automatically done when sending)
packet = packet.__class__(bytes(packet))
# print(packet.show())
checksum_scapy = packet[UDP].chksum
print(hex(checksum_scapy))

# Get the SCTP checksum computed by Scapy
packet = IP()/SCTP()/payload
# packet = IP(raw(packet))  # Build packet (automatically done when sending)
packet = packet.__class__(bytes(packet))
# print(packet.show())
checksum_scapy = packet[SCTP].chksum
print(hex(checksum_scapy))