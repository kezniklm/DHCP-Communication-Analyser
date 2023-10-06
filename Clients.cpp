/**
 * @file Clients.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia metód triedy Clients
 * @date 2023-11-20
 */

#include "Clients.hpp"

/**
 * @brief Konštruktor triedy Client
 * @param IP_address IP adresa
 * @param MAC_address MAC adresa
 */
Client::Client(std::string IP_address, std::string MAC_address)
{
    this->IP_address = IP_address;
    this->MAC_address = MAC_address;
}

/**
 * @brief Vráti IP adresu klienta
 * @return
 */
std::string Client::get_IP_address()
{
    return this->IP_address;
}

/**
 * @brief Nastaví IP adresu podľa zadaného parametra
 * @param IP_address IP_adresa
 */
void Client::set_IP_address(std::string IP_address)
{
    this->IP_address = IP_address;
}

/**
 * @brief Vráti MAC adresu klienta
 * @return
 */
std::string Client::get_MAC_address()
{
    return this->MAC_address;
}

/**
 * @brief Nastaví MAC adresu podľa zadaného parametra
 * @param MAC_address MAC adresa
 */
void Client::set_MAC_address(std::string MAC_address)
{
    this->MAC_address = MAC_address;
}
