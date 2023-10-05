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
 * @brief Trieda predstavujúca klienta v rámci IP prefixu
 */
class Client
{
private:
    std::string IP_address;
    std::string MAC_address;

public:
    /**
     * @brief Konštruktor triedy Client
     * @param IP_address IP adresa
     * @param MAC_address MAC adresa
     */
    Client(std::string IP_address, std::string MAC_address);

    /**
     * @brief Vráti IP adresu klienta
     * @return
     */
    std::string get_IP_address();

    /**
     * @brief Nastaví IP adresu podľa zadaného parametra
     * @param IP_address IP_adresa
     */
    void set_IP_address(std::string IP_address);

    /**
     * @brief Vráti MAC adresu klienta
     * @return
     */
    std::string get_MAC_address();

    /**
     * @brief Nastaví MAC adresu podľa zadaného parametra
     * @param MAC_address MAC adresa
     */
    void set_MAC_address(std::string MAC_address);
};

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
    void add_IP_to_vector(std::string IP_address, std::string MAC_address);

    /**
     * @brief Odstráni IP adresu z vektoru IP_adresses
     * @param IP_address IP adresa na vymazanie
     */
    void delete_from_vector(std::string IP_address, std::string MAC_address);

    /**
     * @brief Zisti či IP adresa patrí do daného prefixu
     * @param IP_address IP adresa
     * @return
     */
    bool match_prefix(const std::string &IP_address);

    /**
     * @brief Zistí, či sa IP adresa nachádza vo vektore IP_adresses
     * @param IP_address IP adresa, ktorá sa má nájsť
     * @return
     */
    bool is_IP_in_vector(std::string IP_address);

    /**
     * @brief Vypíše, prípadne prepíše výstupné okno
     * @param prefix_window Okno ncurses
     * @param number_of_prefix Poradie prefixu
     */
    void write_prefix(WINDOW *prefix_window, int number_of_prefix);

    /**
     * @brief Zistí, či sa nejedná o IP adresu siete alebo broadcastovú adresu siete
     * @param IP_address IP adresa
     * @return
     */
    bool is_network_broadcast_address(std::string IP_address);

    /**
     * @brief Vráti prefix
     * @return
     */
    std::string get_prefix();

    /**
     * @brief Nastaví prefix na honotu new_prefix
     * @param new_prefix
     */
    void set_prefix(std::string new_prefix);

    /**
     * @brief Vráti maximum
     * @return
     */
    int get_maximum();

    /**
     * @brief Nastaví maximum na hodnotu new_maximum
     * @param new_maximum
     */
    void set_maximum(int new_maximum);

    /**
     * @brief Vráti hodnotu used
     * @return
     */
    int get_used();

    /**
     * @brief Nastaví hodnotu used na hodnotu new_used
     * @param new_used
     */
    void set_used(int new_used);

    /**
     * @brief Vráti usage
     * @return
     */
    double get_usage();

    /**
     * @brief Nastaví usage na hodnotu new_usage
     * @param new_usage
     */
    void set_usage(double new_usage);

    std::vector<Client> get_clients_vector();

private:
    std::string prefix;

    int maximum;

    int used;

    double usage;

    /**
     * @brief Klienti, ktoré prefix obsahuje
     */
    std::vector<Client> Clients;

    /**
     * @brief Vypočíta maximálny počet použiteľných IP adries v rámci prefixu
     * @param prefix Prefix s overenou správnosťou
     * @return Maximálne počet použiteľných IP adries v rámci prefixu
     */
    int calculate_maximum_usage(std::string prefix);
};

/**
 * @brief Rozdelí string na časti podľa delimetra
 * @param s String na rozdelenie
 * @param delimiter Delimeter
 * @return
 */
std::vector<std::string> split(const std::string &s, char delimiter);
