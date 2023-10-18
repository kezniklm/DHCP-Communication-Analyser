/**
 * @file Negotiator.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia metód triedy Negotiator
 * @date 2023-11-20
 */

#include "Negotiator.hpp"

/**
 * @brief Konštruktor triedy Negotiator
 * @return
 */
Negotiator::Negotiator(const pcap_pkthdr *header, const u_char *buffer)
{
    this->MAC_adress = get_sender_mac_address(header, buffer);
    this->has_discover = true;
    if (get_receiver_mac_address(header, buffer) != BROADCAST_MAC)
    {
        error_exit("Nekorektný DHCP Discover paket\n");
    }
}

/**
 * @brief Vráti MAC adresu
 * @return
 */
std::string Negotiator::get_MAC_address()
{
    return this->MAC_adress;
}

/**
 * @brief Nastaví MAC adresu na hodnotu new_MAC_address
 * @param new_MAC_address
 */
void Negotiator::set_MAC_address(std::string new_MAC_address)
{
    this->MAC_adress = new_MAC_address;
}

/**
 * @brief Vráti IP adresu
 * @return
 */
std::string Negotiator::get_IP_address()
{
    return this->IP_address;
}

/**
 * @brief Nastaví hodnotu IP adresy na new_IP_address
 * @param new_IP_address
 */
void Negotiator::set_IP_address(std::string new_IP_address)
{
    this->IP_address = new_IP_address;
}