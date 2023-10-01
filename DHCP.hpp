/**
 * @file DHCP.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor triedy DHCP
 * @date 2023-11-20
 */
#pragma once

#include <string>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pcap.h>

class DHCP
{
private:
    bool has_discover = false;
    bool has_offer = false;
    bool has_request = false;
    bool has_ack = false;

public:
    DHCP();

    std::string extractAssignedIP(const pcap_pkthdr *header, const u_char *packet);

    bool is_message_of_type(const pcap_pkthdr *header, const u_char *buffer, const int type);

    struct packet;

    const int Discover = 1;
    const int Offer = 2;
    const int Request = 3;
    const int Acknowledgment = 5;
};

struct DHCP::packet
{
    // DHCP Header
    unsigned char op;           // Message Type (1 byte)
    unsigned char htype;        // Hardware Type (1 byte)
    unsigned char hlen;         // Hardware Address Length (1 byte)
    unsigned char hops;         // Hops (1 byte)
    unsigned int xid;           // Transaction ID (4 bytes)
    unsigned short secs;        // Seconds Elapsed (2 bytes)
    unsigned short flags;       // Flags (2 bytes)
    struct in_addr ciaddr;      // Client IP Address (4 bytes)
    struct in_addr yiaddr;      // Assigned IP Address (4 bytes)
    struct in_addr siaddr;      // Server IP Address (4 bytes)
    struct in_addr giaddr;      // Gateway IP Address (4 bytes)
    unsigned char chaddr[16];   // Client Hardware Address (16 bytes)
    char sname[64];             // Server Name (64 bytes)
    char file[128];             // Boot File Name (128 bytes)
    unsigned int magic_cookie;  // Magic Cookie (4 bytes)
    unsigned char options[308]; // DHCP Options (308 bytes)
};