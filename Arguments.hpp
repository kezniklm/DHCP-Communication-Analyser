/**
 * @file Arguments.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre spracovanie argumentov programu dhcp-stats
 * @date 2023-11-20
 */

#pragma once

#include <pcap.h>
#include <cstring>
#include <syslog.h>

#include "IP_prefix.hpp"

#define FIRST_ARGUMENT 1
#define NEXT_ARGUMENT 1
#define IP_LENGTH 15
#define IP_OCTETS 4
#define ALL_HOSTS_PREFIX "0.0.0.0/0"
#define INCREMENT true
#define DECREMENT false

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
     * @brief Deštruktor triedy Arguments - uvoľní pamäť alokovanú pre inštanciu triedy Arguments
     */
    ~Arguments();

    /**
     * @brief Skontroluje a spracuje argumenty zadané na príkazový riadok
     * @param argc Počet argumentov programu
     * @param argv Argumenty programu
     */
    void check(int argc, char *argv[]);

    /**
     * @brief Pridá klienta do vectoru prefixov
     * @param IP_address IP adresa klienta
     * @param MAC_address MAC adresa klienta
     */
    void add_client_to_prefix_vector(std::string IP_address, std::string MAC_address);

    /**
     * @brief Uvoľní klienta z vectoru prefixov
     * @param IP_address IP adresa klienta
     * @param MAC_address MAC adresa klienta
     */
    void release(std::string IP_address, std::string MAC_address);

    /**
     * @brief Vráti interface
     * @return
     */
    std::string get_interface();

    /**
     * @brief Nastaví interface na hodnotu new_interface
     * @param new_interface Nový interface
     */
    void set_interface(std::string new_interface);

    /**
     * @brief Vráti file descriptor pcap súboru
     * @return
     */
    pcap_t *get_file();

    /**
     * @brief Nastaví file descriptor pcap súboru na new_file
     * @param new_file
     */
    void set_file(pcap_t *new_file);

    /**
     * @brief Vráti prefix_window
     * @return
     */
    WINDOW *get_prefix_window();

    /**
     * @brief Nastaví prefix window na hodnotu new_prefix_window
     * @param new_prefix_window
     */
    void set_prefix_window(WINDOW *new_prefix_window);

    /**
     * @brief Vráti vector IP prefixov
     * @return
     */
    std::vector<IP_prefix> get_IP_prefixes();

    bool is_filename;

    bool is_interface;

    bool is_help;

    bool extensions;

private:
    std::string interface;

    pcap_t *file;

    std::vector<IP_prefix> IP_prefixes;

    WINDOW *prefix_window;

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
     * @param ip_address
     */
    void check_ip_format(std::string ip_address);

    /**
     * @brief Skontroluje octety IPV4 adresy aby boli v intervale <0,255>
     *
     * @param octet
     * @param octet_number
     */
    void check_scope(std::string octet, int *octet_number);

    /**
     * @brief Skontroluje počet bitov masky tak, aby bol v intervale <0,32>
     * @param mask Maska na skontrolovanie
     */
    void check_mask(std::string mask);

    /**
     * @brief Skontroluje, či IP adresa patrí do prefixu
     * @param prefix Prefix
     * @param IP_address IP adresa
     * @return
     */
    bool is_client_in_prefix(IP_prefix &prefix, const std::string &IP_address);

    /**
     * @brief Aktualizuje informácie o prefixe
     * @param prefix Prefix
     * @param operation Operácia - INCREMENT alebo DECREMENT
     */
    void update_prefix_info(IP_prefix &prefix, bool operation, int number_of_prefix);

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
    bool is_prefix_in_vector(IP_prefix target);
};
