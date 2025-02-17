**ARP Spoofing Detection**

This project is a network security tool designed to detect ARP spoofing attacks by analyzing ARP packets in a network. It uses libpcap for packet capture and analysis, and it logs any detected ARP spoofing attempts to a log file.

**Features**

1.Detects ARP spoofing attacks by checking if an IP address is associated with multiple MAC addresses.
2.Logs ARP spoofing alerts with the details of the IP and MAC address involved.
3.Supports offline ARP packet capture using a provided .pcap file.
4.Stores the valid IP-MAC pairings in a local text file (database.txt) for future validation.

**How It Works**

-The program uses libpcap to capture ARP packets from a pcap file.
-For each packet, the program checks if the sender's IP-MAC pairing is consistent with the database. If it’s different, an ARP spoofing attack is detected, and the information is logged.
-The program maintains an ARP table (database.txt) where it stores the valid IP-MAC associations

**Prerequisites**

-libpcap library installed for packet capture functionality.
-MinGW or MSYS to compile and run the program on Windows.
-GCC installed to compile the code.

**Getting Started**

1.Clone the repository or download the project files.
2.Ensure libpcap and Scapy are installed.
pip install scapy
3.Compile the program using the following command:
gcc -o arp_detector arp_detector.c -lpcap
4.To generate a custom ARP packet, you can use the provided Scapy script:
This script creates an ARP request packet and writes it to a .pcap file (generated_arp.pcap):
python generate_arp_pcap.py
5.Run the ARP spoofing detection program with the generated .pcap file:
./arp_detector generated_arp.pcap
The program will process the ARP packets and log any detected spoofing attempts.

