/**
 * @file dhcp-stats.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor analyzátora percentuálneho využitia sieťových prefixov dhcp-stats
 * @date 2023-11-20
 */

#pragma once

#include <csignal>

#include "Arguments.hpp"
#include "DHCP.hpp"

#define ERROR -1
#define DHCP_SETTINGS "(udp port 67 or udp port 68) and ip"
#define UNDEFINED_IP "0.0.0.0"

/**
 * @brief Štruktúra obsahujúca ukazatele na objekty, ktoré musia byť uvoľnené
 */
struct to_release
{
    class Arguments *arguments;
    struct bpf_program *bpf;
    pcap_t *opened_session;
};

/**
 * @brief Spracuje DHCP pakety a vypíše štatistiky podľa prichádzajúcich DHCP paketov
 * @param args Argumenty
 * @param header Hlavička paketu
 * @param buffer Paket
 */
void packet_handler(u_char *args, const pcap_pkthdr *header, const u_char *buffer);

/**
 * @brief Zachytí SIGINT signál a uvoľní využívanú pamäť
 * @param signum
 */
void signal_handler(int signum);
