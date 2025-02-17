# PowerShell script to compile and run ARP Parser with database.txt

$INCLUDE_PATH = "C:\Program Files\Npcap\Include"
$LIB_PATH = "C:\Program Files\Npcap\Lib\x64"

# Compile the C program
gcc -o arp_parser arp.c -I"$INCLUDE_PATH" -L"$LIB_PATH" -lpcap

# Run the ARP parser with sample PCAP file
.\arp_parser file.pcap

# Display output
Write-Output "Execution completed. Check for spoofing alerts in the console."

