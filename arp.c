/*#ifdef _WIN32
    #define _CRT_SECURE_NO_WARNINGS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "Ws2_32.lib")
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define MAX_SIZE_ARP_TABLE 2000

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ARP {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t opcode;
    u_char mac_sender[ETHER_ADDR_LEN];
    u_char ip_sender[4];
    u_char mac_target[ETHER_ADDR_LEN];
    u_char ip_target[4];
};

struct arp_entry {
    char ip[16];
    char mac[18];
};

struct arp_entry arp_table[MAX_SIZE_ARP_TABLE];
int arp_table_size = 0;

char* database_file_name = "database.txt";

void hexStringToStringMAC(const u_char* macAddress, char* result) {
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x",
        macAddress[0], macAddress[1], macAddress[2],
        macAddress[3], macAddress[4], macAddress[5]);
}

void hexStringToStringIP(const u_char* ipAddress, char* string_ip) {
    sprintf(string_ip, "%d.%d.%d.%d",
        ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
}

void loadARPTable() {
    FILE* file = fopen(database_file_name, "r");
    if (!file) {
        printf("Error: Could not open database.txt. Creating a new one.\n");
        return;
    }

    while (fscanf(file, "%s %s", arp_table[arp_table_size].ip, arp_table[arp_table_size].mac) == 2) {
        arp_table_size++;
    }

    fclose(file);
}

int checkSpoofing(const char* ip, const char* mac) {
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip, ip) == 0) {
            if (strcmp(arp_table[i].mac, mac) != 0) {
                return 1;  // Spoofing detected!
            }
            return 0;  // Valid entry
        }
    }
    return -1;  // Not in database
}

void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    const struct sniff_ethernet* ethernet = (struct sniff_ethernet*)(packet);
    const struct sniff_ARP* arpData = (struct sniff_ARP*)(packet + SIZE_ETHERNET);

    char mac_sender[18], mac_target[18], ip_sender[16], ip_target[16];
    hexStringToStringMAC(arpData->mac_sender, mac_sender);
    hexStringToStringMAC(arpData->mac_target, mac_target);
    hexStringToStringIP(arpData->ip_sender, ip_sender);
    hexStringToStringIP(arpData->ip_target, ip_target);

    int result = checkSpoofing(ip_sender, mac_sender);
    if (result == 1) {
        printf("⚠️ ARP Spoofing Detected: IP %s is being used by %s instead of expected MAC\n", ip_sender, mac_sender);
    } else if (result == -1) {
        printf("ℹ️ New Entry: IP %s with MAC %s (Not in database)\n", ip_sender, mac_sender);
    } else {
        printf("✅ Valid ARP: IP %s -> MAC %s\n", ip_sender, mac_sender);
    }
}

int main(int argc, char* argv[]) {
    pcap_t* handle;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (argc != 2) {
        printf("Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    loadARPTable();

    handle = pcap_open_offline(argv[1], error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Cannot open pcap file: %s\n", error_buffer);
        return 2;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);
    return 0;
}



#ifdef _WIN32
    #define _CRT_SECURE_NO_WARNINGS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "Ws2_32.lib")
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define MAX_SIZE_ARP_TABLE 2000

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ARP {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t opcode;
    u_char mac_sender[ETHER_ADDR_LEN];
    u_char ip_sender[4];
    u_char mac_target[ETHER_ADDR_LEN];
    u_char ip_target[4];
};

struct arp_entry {
    char ip[16];
    char mac[18];
};

struct arp_entry arp_table[MAX_SIZE_ARP_TABLE];
int arp_table_size = 0;

char* database_file_name = "database.txt";

// Function to convert MAC address to a human-readable string
void hexStringToStringMAC(const u_char* macAddress, char* result) {
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x",
        macAddress[0], macAddress[1], macAddress[2],
        macAddress[3], macAddress[4], macAddress[5]);
}

// Function to convert IP address to a human-readable string
void hexStringToStringIP(const u_char* ipAddress, char* string_ip) {
    sprintf(string_ip, "%d.%d.%d.%d",
        ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
}

// Load the ARP table from the database.txt file
void loadARPTable() {
    FILE* file = fopen(database_file_name, "r");
    if (!file) {
        printf("Error: Could not open database.txt. Creating a new one.\n");
        return;
    }

    while (fscanf(file, "%s %s", arp_table[arp_table_size].ip, arp_table[arp_table_size].mac) == 2) {
        arp_table_size++;
    }

    fclose(file);
}

int isValidIP(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        printf("❌ Invalid IP address format: %s\n", ip);
        return 0;  // Invalid IP format
    }

    // Convert to a 32-bit unsigned integer (network byte order)
    uint32_t ip_value = ntohl(addr.s_addr);

    // Assume valid subnet is 192.168.1.0/24 (range: 192.168.1.0 to 192.168.1.255)
    uint32_t network_start = ntohl(inet_addr("192.168.0.0"));
    uint32_t network_end = network_start + 65535;  // Correct calculation for the end of the subnet

    if (ip_value >= network_start && ip_value <= network_end) {
        return 1;  // Valid IP within range
    } else {
        printf("❌ IP address out of range: %s\n", ip);
        return 0;  // IP not in the valid range
    }
}



int isValidMAC(const char* mac) {
    // Check if the MAC address is in a valid format (XX:XX:XX:XX:XX:XX)
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':') {
                return 0;  // Invalid separator
            }
        } else {
            if (!isxdigit(mac[i])) {
                return 0;  // Invalid hex digit
            }
        }
    }
    return 1;  // Valid MAC address
}

// Check and add the IP-MAC pair to the database, detect ARP spoofing
int checkAndAddEntry(const char* ip, const char* mac) {
    // Validate IP and MAC
    if (!isValidIP(ip)) {
        printf("❌ Invalid IP address: %s\n", ip);
        return 0;
    }

    if (!isValidMAC(mac)) {
        printf("❌ Invalid MAC address: %s\n", mac);
        return 0;
    }

    // Check if the IP is already in the database and compare MAC address
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip, ip) == 0) {
            if (strcmp(arp_table[i].mac, mac) != 0) {
                printf("⚠️ ARP Spoofing Detected: IP %s is being used by %s instead of expected MAC %s\n", ip, mac, arp_table[i].mac);
                return 0;  // ARP spoofing detected
            }
            printf("✅ Valid ARP: IP %s -> MAC %s\n", ip, mac);
            return 1;  // Valid entry, no action needed
        }
    }

    // Add new IP-MAC pair to the database
    FILE *file = fopen(database_file_name, "a");
    if (file) {
        fprintf(file, "%s %s\n", ip, mac);
        fclose(file);
        printf("ℹ️ New Entry Added: IP %s with MAC %s\n", ip, mac);
        return 1;  // Successfully added new entry
    } else {
        printf("❌ Could not open database.txt to add new entry\n");
        return 0;  // Error in opening the file
    }
}

// Packet handler for ARP packet processing
void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    const struct sniff_ethernet* ethernet = (struct sniff_ethernet*)(packet);
    const struct sniff_ARP* arpData = (struct sniff_ARP*)(packet + SIZE_ETHERNET);

    char mac_sender[18], mac_target[18], ip_sender[16], ip_target[16];
    hexStringToStringMAC(arpData->mac_sender, mac_sender);
    hexStringToStringMAC(arpData->mac_target, mac_target);
    hexStringToStringIP(arpData->ip_sender, ip_sender);
    hexStringToStringIP(arpData->ip_target, ip_target);

    // Debug print for IP sender
    printf("IP Sender: %s\n", ip_sender);

    // Detect and add the IP-MAC pair, check for spoofing
    checkAndAddEntry(ip_sender, mac_sender);
}

int main(int argc, char* argv[]) {
    pcap_t* handle;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (argc != 2) {
        printf("Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    loadARPTable();  // Load the ARP table from database.txt

    // Open the pcap file for offline processing
    handle = pcap_open_offline(argv[1], error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Cannot open pcap file: %s\n", error_buffer);
        return 2;
    }

    // Process packets in the pcap file
    pcap_loop(handle, 0, my_packet_handler, NULL);  // Start packet processing
    pcap_close(handle);

    return 0;
}
*/

#ifdef _WIN32
    #define _CRT_SECURE_NO_WARNINGS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "Ws2_32.lib")
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define MAX_SIZE_ARP_TABLE 2000

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ARP {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t opcode;
    u_char mac_sender[ETHER_ADDR_LEN];
    u_char ip_sender[4];
    u_char mac_target[ETHER_ADDR_LEN];
    u_char ip_target[4];
};

struct arp_entry {
    char ip[16];
    char mac[18];
};

struct arp_entry arp_table[MAX_SIZE_ARP_TABLE];
int arp_table_size = 0;

char* database_file_name = "database.txt";

// Function to convert MAC address to a human-readable string
void hexStringToStringMAC(const u_char* macAddress, char* result) {
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x",
        macAddress[0], macAddress[1], macAddress[2],
        macAddress[3], macAddress[4], macAddress[5]);
}

// Function to convert IP address to a human-readable string
void hexStringToStringIP(const u_char* ipAddress, char* string_ip) {
    sprintf(string_ip, "%d.%d.%d.%d",
        ipAddress[0], ipAddress[1], ipAddress[2], ipAddress[3]);
}

// Load the ARP table from the database.txt file
void loadARPTable() {
    FILE* file = fopen(database_file_name, "r");
    if (!file) {
        printf("Error: Could not open database.txt. Creating a new one.\n");
        return;
    }

    while (fscanf(file, "%s %s", arp_table[arp_table_size].ip, arp_table[arp_table_size].mac) == 2) {
        arp_table_size++;
    }

    fclose(file);
}

int isValidIP(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        printf("❌ Invalid IP address format: %s\n", ip);
        return 0;  // Invalid IP format
    }

    // Convert to a 32-bit unsigned integer (network byte order)
    uint32_t ip_value = ntohl(addr.s_addr);

    // Assume valid subnet is 192.168.1.0/24 (range: 192.168.1.0 to 192.168.1.255)
    uint32_t network_start = ntohl(inet_addr("192.168.0.0"));
    uint32_t network_end = network_start + 65535;  // Correct calculation for the end of the subnet

    if (ip_value >= network_start && ip_value <= network_end) {
        return 1;  // Valid IP within range
    } else {
        printf("❌ IP address out of range: %s\n", ip);
        return 0;  // IP not in the valid range
    }
}

int isValidMAC(const char* mac) {
    // Check if the MAC address is in a valid format (XX:XX:XX:XX:XX:XX)
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':') {
                return 0;  // Invalid separator
            }
        } else {
            if (!isxdigit(mac[i])) {
                return 0;  // Invalid hex digit
            }
        }
    }
    return 1;  // Valid MAC address
}

// Function to log ARP spoofing alerts to a log file
void logAlert(const char* ip, const char* mac) {
    // Define the full path for the log file
    const char* log_file_path = "C:\\Users\\vpm64\\OneDrive\\Desktop\\ARP\\alert_log.txt";

    // Open the log file in append mode
    FILE* file = fopen(log_file_path, "a");
    if (file == NULL) {
        printf("❌ Error opening log file: %s\n", strerror(errno));
        return;
    }

    // Write the alert to the log file
    fprintf(file, "ALERT: ARP Spoofing detected! IP: %s, MAC: %s\n", ip, mac);
    
    // Close the file
    fclose(file);
    printf("⚠️ ARP Spoofing Alert logged for IP %s, MAC %s\n", ip, mac);
}


// Check and add the IP-MAC pair to the database, detect ARP spoofing
int checkAndAddEntry(const char* ip, const char* mac) {
    // Validate IP and MAC
    if (!isValidIP(ip)) {
        printf("❌ Invalid IP address: %s\n", ip);
        return 0;
    }

    if (!isValidMAC(mac)) {
        printf("❌ Invalid MAC address: %s\n", mac);
        return 0;
    }

    // Check if the IP is already in the database and compare MAC address
    for (int i = 0; i < arp_table_size; i++) {
        if (strcmp(arp_table[i].ip, ip) == 0) {
            if (strcmp(arp_table[i].mac, mac) != 0) {
                printf("⚠️ ARP Spoofing Detected: IP %s is being used by %s instead of expected MAC %s\n", ip, mac, arp_table[i].mac);
                logAlert(ip, mac);  // Log the alert
                return 0;  // ARP spoofing detected
            }
            printf("✅ Valid ARP: IP %s -> MAC %s\n", ip, mac);
            return 1;  // Valid entry, no action needed
        }
    }

    // Add new IP-MAC pair to the database
    FILE *file = fopen(database_file_name, "a");
    if (file) {
        fprintf(file, "%s %s\n", ip, mac);
        fclose(file);
        printf("ℹ️ New Entry Added: IP %s with MAC %s\n", ip, mac);
        return 1;  // Successfully added new entry
    } else {
        printf("❌ Could not open database.txt to add new entry\n");
        return 0;  // Error in opening the file
    }
}

// Packet handler for ARP packet processing
void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    const struct sniff_ethernet* ethernet = (struct sniff_ethernet*)(packet);
    const struct sniff_ARP* arpData = (struct sniff_ARP*)(packet + SIZE_ETHERNET);

    char mac_sender[18], mac_target[18], ip_sender[16], ip_target[16];
    hexStringToStringMAC(arpData->mac_sender, mac_sender);
    hexStringToStringMAC(arpData->mac_target, mac_target);
    hexStringToStringIP(arpData->ip_sender, ip_sender);
    hexStringToStringIP(arpData->ip_target, ip_target);

    // Debug print for IP sender
    printf("IP Sender: %s\n", ip_sender);

    // Detect and add the IP-MAC pair, check for spoofing
    checkAndAddEntry(ip_sender, mac_sender);
}

int main(int argc, char* argv[]) {
    pcap_t* handle;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (argc != 2) {
        printf("Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    loadARPTable();  // Load the ARP table from database.txt

    // Open the pcap file for offline processing
    handle = pcap_open_offline(argv[1], error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Cannot open pcap file: %s\n", error_buffer);
        return 2;
    }

    // Process packets in the pcap file
    pcap_loop(handle, 0, my_packet_handler, NULL);  // Start packet processing
    pcap_close(handle);

    return 0;
}
