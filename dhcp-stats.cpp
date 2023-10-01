/**
 * @file dhcp-stats.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia analyzátora percentuálneho využitia sieťových prefixov dhcp-stats
 * @date 2023-11-20
 */

#include "dhcp-stats.hpp"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    Arguments *arguments = (Arguments *)(args);
    static class DHCP dhcp;
    if (dhcp.is_message_of_type(header, buffer, dhcp.Acknowledgment))
    {
        std::string IP = dhcp.extractAssignedIP(header, buffer);
        arguments->assign_ip_to_prefixes(IP);
    }
}

int main(int argc, char *argv[])
{
    initscr();                                     // Inicializace NCurses
    cbreak();                                      // Přerušení řádkového bufferování
    noecho();                                      // Nezobrazovat znaky na obrazovce
    curs_set(FALSE);                               // Skrýt kurzor
    keypad(stdscr, TRUE);                          // Povolit speciální klávesy (např. šipky)
    WINDOW *prefix_window = newwin(10, 120, 0, 0); // Vytvořte okno s určitými rozměry a pozicí
    mvwprintw(prefix_window, 0, 1, "IP-Prefix");   //  "
    mvwprintw(prefix_window, 0, 20, "Max-hosts");
    mvwprintw(prefix_window, 0, 40, "Allocated addresses");
    mvwprintw(prefix_window, 0, 60, "Utilization");
    wrefresh(prefix_window);
    Arguments arguments(prefix_window);
    arguments.check(argc, argv);
    pcap_t *opened_session;
    struct bpf_program fp;
    char errbuff[PCAP_ERRBUF_SIZE];
    std::string filter = DHCP_SETTINGS;
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

    if (pcap_compile(opened_session, &fp, filter.c_str(), 0, pNet) == ERROR)
    {
        error_exit("Zlyhanie funkcie pcap_compile");
    }

    if (pcap_setfilter(opened_session, &fp) == ERROR)
    {
        error_exit("Nie je možné použiť daný filter");
    }

    pcap_loop(opened_session, 0, packet_handler, (u_char *)&arguments);

    pcap_freecode(&fp);
    pcap_close(opened_session);

    endwin();

    exit(EXIT_SUCCESS);
}