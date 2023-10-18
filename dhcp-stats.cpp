/**
 * @file dhcp-stats.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia analyzátora percentuálneho využitia sieťových prefixov dhcp-stats
 * @date 2023-11-20
 */

#include "dhcp-stats.hpp"

/**
 * @brief Globálny ukazateľ - nutný pre uvoľnenie pamäte v signal handleri
 */
struct to_release *to_release;

/**
 * @brief Zachytí SIGINT signál a uvoľní využívanú pamäť
 * @param signum
 */
void signal_handler(int signum)
{
    if (to_release->arguments)
    {
        if (to_release->arguments->get_prefix_window() != nullptr)
        {
            delwin(to_release->arguments->get_prefix_window());
        }
        to_release->arguments->~Arguments();
    }

    if (to_release->bpf)
    {
        pcap_freecode(to_release->bpf);
    }

    if (to_release->opened_session)
    {
        pcap_close(to_release->opened_session);
    }

    closelog();
    endwin();
    exit(SIGINT);
}

/**
 * @brief Spracuje DHCP pakety a vypíše štatistiky podľa prichádzajúcich DHCP paketov
 * @param args Argumenty
 * @param header Hlavička paketu
 * @param buffer Paket
 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    Arguments *arguments = (Arguments *)(args);
    static class DHCP dhcp;

    if (dhcp.verify_dhcp_negotiation(header, buffer))
    {
        std::string IP_address = dhcp.extract_yiaddr(header, buffer);
        std::string MAC_address = get_receiver_mac_address(header, buffer);
        if (MAC_address == BROADCAST_MAC)
        {
            MAC_address = dhcp.extract_chaddr(header, buffer);
        }

        if (IP_address == "0.0.0.0")
        {
            IP_address = dhcp.get_dest_IP(header, buffer);
        }

        if (dhcp.check_MAC_IP_pair(IP_address, MAC_address))
        {
            arguments->add_client_to_prefix_vector(IP_address, MAC_address);
        }
    }
    else if (arguments->extensions && dhcp.is_release(header, buffer))
    {
        std::string IP_address = dhcp.extract_ciaddr(header, buffer);
        std::string MAC_address = get_sender_mac_address(header, buffer);
        arguments->release(IP_address, MAC_address);
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);

    openlog("dhcp-client", LOG_PID, LOG_USER);

    initscr();                                     // Inicializácia NCurses
    cbreak();                                      // Přerušenie řiadkového bufferovania
    noecho();                                      // Vypnutie zobrazovania znakov na obrazovke
    curs_set(FALSE);                               // Skrytie kurzora
    keypad(stdscr, TRUE);                          // Povolenie šípiek
    WINDOW *prefix_window = newwin(10, 120, 0, 0); // Vytvorenie okna
    mvwprintw(prefix_window, 0, 1, "IP-Prefix");
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

    if (arguments.is_help)
    {
        delwin(prefix_window);
        endwin();
        printf("Názov:\n    dhcp-stats - analyzátor percentuálneho využitia sieťových prefixov\n\nPoužitie:\n  ./dhcp-stats [-r <filename>] [-i <interface-name>]  [--ext] <ip-prefix> [ <ip-prefix> [ ... ] ]\n\n  ./dhcp-stats --help \n\n  ./dhcp-stats -h \nPopis:\n    Sieťový analyzátor, ktorý umožňuje získanie percentuálneho využitia sieťových prefixov\n");
        std::exit(EXIT_SUCCESS);
    }
    else if (arguments.is_interface)
    {
        if (pcap_lookupnet(arguments.get_interface().c_str(), &pNet, &pMask, errbuff) == ERROR)
        {
            error_exit("Nepodarilo sa získať sieťovú masku\n");
        }
        opened_session = pcap_open_live(arguments.get_interface().c_str(), BUFSIZ, 1, 1000, errbuff);
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
        opened_session = arguments.get_file();
    }

    if (pcap_compile(opened_session, &fp, filter.c_str(), 0, pNet) == ERROR)
    {
        error_exit("Zlyhanie funkcie pcap_compile");
    }

    if (pcap_setfilter(opened_session, &fp) == ERROR)
    {
        error_exit("Nie je možné použiť daný filter");
    }

    struct to_release release;
    to_release = &release;
    to_release->arguments = &arguments;
    to_release->opened_session = opened_session;
    to_release->bpf = &fp;

    // Ošetrenie leakov pamäte - string filter
    if (!filter.empty())
    {
        filter.~basic_string();
    }

    // Nekonečný cyklus - aby nebolo okno NCurses ukončené hneď po spracovaní súboru
    while (true)
    {
        pcap_loop(opened_session, 0, packet_handler, (u_char *)&arguments);
    }

    pcap_freecode(&fp);
    pcap_close(opened_session);

    closelog();

    delwin(prefix_window);
    endwin();

    exit(EXIT_SUCCESS);
}