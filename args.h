/**
 * @file args.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre spracovanie argumentov programu dhcp-stats
 * @date 2023-11-20
 */

#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <string>
#include <pcap.h>
#include <iostream>
#include <bitset>
#include <string>
#include <sstream>

#include "error.h"

#define FIRST_ARGUMENT 1
#define NEXT_ARGUMENT 1
#define IP_LENGTH 15
#define IP_OCTETS 4
#define NETWORK_ADRESS 1
#define BROADCAST_ADRESS 1

class IP_prefix
{
private:
    int calculate_maximum_usage(std::string prefix);

public:
    IP_prefix(std::string prefix);
    double calculate_usage(std::string prefix);
    std::string prefix;
    int maximum;
    int used;
    double usage;
    std::vector<std::string> IP_address;
};

class Arguments
{
public:
    Arguments();
    void check(int argc, char *argv[]);
    bool check_overlap(std::string prefix);

    bool is_interface;
    std::string interface;
    bool is_filename;
    pcap_t *file;
    std::vector<IP_prefix> IP_prefixes;

private:
    /**
     * @brief Skontroluje prítomnosť a korektnosť druhého argumentu po aktuálnom argumente
     * @param argv Vstupné argumenty
     * @param argument_number Spracovávaný argument
     */
    void is_another_argument(char *argv[], int argument_number);

    bool is_correct_prefix(std::string prefix);


    bool is_prefix_in_vector(const IP_prefix & target);

    /**
     * @brief Skontroluje octety IPV4 adresy aby boli v intervale <0,255>
     *
     * @param octet
     * @param octet_num
     */
    void check_scope(std::string octet, int *octet_num);

    void check_mask(std::string mask);

    bool is_in_interval(std::string to_check, int start, int end);

    void clear_prefix_vector();

    /**
     * @brief Skontroluje formát zadanej IPV4 adresy
     *
     * @param ip_adress
     */
    void check_ip_format(std::string ip_address);
};
