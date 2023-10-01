/**
 * @file DHCP.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia operácií s DHCP paketmi
 * @date 2023-11-20
 */

#include "DHCP.hpp"

DHCP::DHCP()
{
}

std::string DHCP::extractAssignedIP(const struct pcap_pkthdr *header, const u_char *packet)
{
    DHCP::packet *dhcp_header = (DHCP::packet *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    struct in_addr assigned_ip = dhcp_header->yiaddr;
    return inet_ntoa(assigned_ip);
}

bool DHCP::is_message_of_type(const struct pcap_pkthdr *header, const u_char *buffer, const int type)
{
    u_char *options = (u_char *)buffer + 240; // DHCP options start at byte 240
    int option_len = header->caplen - 240;

    for (int i = 0; i < option_len;)
    {
        int option_code = options[i++];
        int option_length = options[i++];
        if (option_code == 53 && option_length == 1)
        {
            int dhcp_msg_type = options[i++];
            if (dhcp_msg_type == type)
            {
                return true;
            }
        }
    }
    return false;
}