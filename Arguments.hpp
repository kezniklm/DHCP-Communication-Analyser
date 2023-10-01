/**
 * @file Arguments.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre spracovanie argumentov programu dhcp-stats
 * @date 2023-11-20
 */

#pragma once

#include <pcap.h>
#include <cstring>

#include "IP_prefix.hpp"

#define FIRST_ARGUMENT 1
#define NEXT_ARGUMENT 1
#define IP_LENGTH 15
#define IP_OCTETS 4

/**
 * @brief Trieda, ktorej úlohou je spracovanie argumentov
 */
class Arguments
{
public:
    /**
     * @brief Konštruktor triedy Arguments - inicializuje inštančné premenné
     */
    Arguments(WINDOW *prefix_window);

    /**
     * @brief Skontroluje a spracuje argumenty zadané na príkazový riadok
     * @param argc Počet argumentov programu
     * @param argv Argumenty programu
     */
    void check(int argc, char *argv[]);
    void assign_ip_to_prefixes(std::string IP_address);

    bool is_interface;
    std::string interface;
    bool is_filename;
    bool extensions;
    pcap_t *file;
    std::vector<IP_prefix> IP_prefixes;
    WINDOW *prefix_window;

private:
    /**
     * @brief Skontroluje prítomnosť a korektnosť druhého argumentu po aktuálnom argumente
     * @param argv Vstupné argumenty
     * @param argument_number Spracovávaný argument
     */
    void is_another_argument(char *argv[], int argument_number);

    /**
     * @brief Skontroluje korektnosť prefixu
     * @param prefix Prefix, ktorý sa má skontrolovať
     * @return
     */
    bool is_correct_prefix(std::string prefix);

    /**
     * @brief Skontroluje, či sa jedná o adresu siete a nie rozhrania
     * @param prefix Prefix, ktorý sa má skontrolovať
     */
    void check_overlap(std::string prefix);

    /**
     * @brief Skontroluje formát zadanej IPV4 adresy
     *
     * @param ip_adress
     */
    void check_ip_format(std::string ip_address);

    /**
     * @brief Skontroluje octety IPV4 adresy aby boli v intervale <0,255>
     *
     * @param octet
     * @param octet_num
     */
    void check_scope(std::string octet, int *octet_num);

    /**
     * @brief Skontroluje počet bitov masky tak, aby bol v intervale <0,32>
     * @param mask Maska na skontrolovanie
     */
    void check_mask(std::string mask);

    /**
     * @brief Kontroluje, či je číslo v zadanom intervale
     * @param to_check Číslo na skontrolovanie
     * @param start Začiatok intervalu
     * @param end Koniec intervalu
     * @return
     */
    bool is_in_interval(std::string to_check, int start, int end);

    /**
     * @brief Skontroluje, či zadaný prefix sa už nachádza vo vektore IP_prefixes
     * @param target Prefix, ktorý má byť skontrolovaný
     * @return
     */
    bool is_prefix_in_vector(const IP_prefix &target);
};
