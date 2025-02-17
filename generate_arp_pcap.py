from scapy.all import ARP, Ether, wrpcap

# Create a basic ARP request packet
arp_request = ARP(pdst="192.168.1.1")  # Target IP
ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address

# Combine Ethernet frame and ARP request
packet = ether_frame / arp_request

# Write the packet to a .pcap file
try:
    wrpcap("generated_arp.pcap", packet)
    print("ARP packet generated in generated_arp.pcap")
except Exception as e:
    print(f"Error: {e}")
