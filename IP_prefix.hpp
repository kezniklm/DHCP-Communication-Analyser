/**
 * @file IP_prefix.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor triedy IP_prefix pre spracovanie IP prefixov
 * @date 2023-11-20
 */

#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <bitset>
#include <ncurses.h>

#include "error.hpp"

#define NETWORK_ADRESS 1
#define BROADCAST_ADRESS 1

/**
 * @brief Trieda obsahujúca informácie o IP prefixe a metódy s ním spojené
 */
class IP_prefix
{
public:
    /**
     * @brief Konštruktor triedy IP_prefix
     * @param prefix Prefix s overenou správnosťou
     */
    IP_prefix(std::string prefix);

    /**
     * @brief Vypočíta percentuálne využitie prefixu
     * @param prefix Prefix s overenou správnosťou
     * @return Percentuálne využitie prefixu
     */
    double calculate_usage(std::string prefix);

    /**
     * @brief Pridá IP adresu do vektoru IP_adresses
     * @param IP_address IP adresa na pridanie
     */
    void add_IP_to_vector(std::string IP_address);

    /**
     * @brief Odstráni IP adresu z vektoru IP_adresses
     * @param IP_address IP adresa na vymazanie
     */
    void delete_IP_from_vector(std::string IP_address);

    bool match_prefix(const std::string &ip);

    /**
     * @brief Zistí, či sa IP adresa nachádza vo vektore IP_adresses
     * @param IP_address IP adresa, ktorá sa má nájsť
     * @return
     */
    bool is_IP_in_vector(std::string IP_address);

    std::string prefix;
    int maximum;
    int used;
    double usage;
    /**
     * @brief IP adresy, ktoré prefix obsahuje
     */
    std::vector<std::string> IP_addresses;
    void write_prefix(WINDOW *prefix_window, int number_of_prefix);
    bool is_network_broadcast_address(std::string IP_address);

private:
    /**
     * @brief Vypočíta maximálny počet použiteľných IP adries v rámci prefixu
     * @param prefix Prefix s overenou správnosťou
     * @return Maximálne počet použiteľných IP adries v rámci prefixu
     */
    int calculate_maximum_usage(std::string prefix);
};

std::vector<std::string> split(const std::string &s, char delimiter);
