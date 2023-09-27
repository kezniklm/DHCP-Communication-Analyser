/**
 * @file dhcp-stats.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia analyzátora percentuálneho využitia sieťových prefixov dhcp-stats
 * @date 2023-11-20
 */

#include "dhcp-stats.hpp"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    
}

int main(int argc, char *argv[])
{
    Arguments arguments;
    arguments.check(argc, argv);
    // printf("\n\n%s\n\n", arguments.interface.c_str());
    pcap_t *opened_session;
    struct bpf_program fp;
    char *filter, errbuff[PCAP_ERRBUF_SIZE];
    bpf_u_int32 pMask, pNet;

    if (arguments.is_interface)
    {
        if (pcap_lookupnet(arguments.interface.c_str(), &pNet, &pMask, errbuff) == ERROR)
        {
            error_exit("Nepodarilo sa získať sieťovú masku\n");
        }
        opened_session = pcap_open_live(arguments.interface.c_str(), BUFSIZ, 1, 1000, errbuff);
        if (opened_session == NULL)
        {
            error_exit("Nebolo možné otvoriť zadaný interface");
        }

        if (pcap_datalink(opened_session) != DLT_EN10MB)
        {
            error_exit("Interface neposkytuje ethernetove hlavicky");
        }
    }
    else
    {
        opened_session = arguments.file;
    }
}