/**
 * @file DHCP.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor triedy DHCP
 * @date 2023-11-20
 */

#pragma once

#include <string>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

#include "Error.hpp"
#include "Negotiator.hpp"

class DHCP
{
private:
    const int Discover = 1;
    const int Offer = 2;
    const int Request = 3;
    const int Acknowledgment = 5;
    const int Release = 7;

    std::vector<Negotiator> clients_without_ip;

public:
    /**
     * @brief Konštruktor triedy DHCP
     */
    DHCP();

    /**
     * @brief Extrahuje yiaddr IP adresu z DHCP paketu
     * @param header Hlavička pcap
     * @param packet Paket
     * @return
     */
    std::string extract_yiaddr(const pcap_pkthdr *header, const u_char *packet);

    /**
     * @brief Extrahuje ciaddr IP adresu z DHCP paketu
     * @param header Hlavička pcap
     * @param packet Paket
     * @return
     */
    std::string extract_ciaddr(const pcap_pkthdr *header, const u_char *packet);

    /**
     * @brief Extrahuje chaddr - MAC adresu z DHCP paketu
     * @param header Hlavička pcap
     * @param packet Paket
     * @return
     */
    std::string extract_chaddr(const pcap_pkthdr *header, const u_char *packet);

    /**
     * @brief Vráti destination IP z paketu
     * @param header Hlavička pcap
     * @param packet Paket
     * @return
     */
    std::string get_dest_IP(const pcap_pkthdr *header, const u_char *packet);

    /**
     * @brief Overí, či je správa typu type
     * @param header Hlavička pcap
     * @param buffer Paket
     * @param type Typ správy
     * @return
     */
    bool is_message_of_type(const pcap_pkthdr *header, const u_char *buffer, const int type);

    /**
     * @brief Uvoľní pridelenú IP adresu v prípade správy DHCP RELEASE
     * @param header Hlavička pcap
     * @param buffer Paket
     * @return
     */
    bool is_release(const pcap_pkthdr *header, const u_char *buffer);

    /**
     * @brief Overí, či DHCP "handshake" je v korektnom poradí
     * @param header pcap
     * @param buffer Paket
     * @return
     */
    bool verify_dhcp_negotiation(const pcap_pkthdr *header, const u_char *buffer);

    /**
     * @brief Overí, či poradie Discovery, Offer, Request a Acknowledge správ je korektné
     * @param MAC MAC adresa clienta
     * @param type Typ správy na overenie
     */
    void is_DORA_continuous(const std::string MAC, const int type);

    /**
     * @brief Skontroluje, či pár IP:MAC adresa sedí s tým, čo bolo poslané v REQUEST message
     * @param IP_address IP adresa
     * @param MAC_address MAC adresa
     * @return
     */
    bool check_MAC_IP_pair(std::string IP_address, std::string MAC_address);

    /**
     * @brief Vyhľadá clienta podľa MAC adresy vo vektori clients_without_ip
     * @param MAC_address
     * @return
     */
    bool is_in_clients_without_ip(std::string MAC_address);

    /**
     * @brief Skontroluje, či DORA proces prebehol úspešne
     * @param MAC MAC adresa zariadenia
     * @return
     */
    bool is_negotiation_complete(std::string MAC);

    /**
     * @brief Pridá do zoznamu clients_without_ip klientovi žiadanú IP adresu
     * @param header Pcap hlavička
     * @param buffer Paket
     */
    void add_requested_ip(const pcap_pkthdr *header, const u_char *buffer);

    /**
     * @brief Nájde klienta s MAC adresou a podľa typu nastaví, aký typ správy aktuálne klient má
     * @param MAC MAC adresa klienta
     * @param type Typ správy
     */
    void search_MAC_and_modify_flag(const std::string MAC, const int type);

    /**
     * @brief Hlavička DHCP paketu
     */
    struct packet;
};

/**
 * @brief Hlavička DHCP paketu
 */
struct DHCP::packet
{
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
