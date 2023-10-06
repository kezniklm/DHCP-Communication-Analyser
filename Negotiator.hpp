/**
 * @file Negotiator.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor triedy Negotiator
 * @date 2023-11-20
 */

#include <string>
#include <pcap.h>

#include "error.hpp"
#include "Utils.hpp"

#define BROADCAST_MAC "FF:FF:FF:FF:FF:FF"

/**
 * @brief Trieda Negotiator predstavujúca priebeh DHCP "handshaku"
 */
class Negotiator
{
private:
    std::string MAC_adress;

    std::string IP_address;

public:
    bool has_discover = true;

    bool has_offer = false;

    bool has_request = false;

    bool has_ack = false;

    /**
     * @brief Konštruktor triedy Negotiator
     * @return
     */
    Negotiator(const pcap_pkthdr *header, const u_char *buffer);

    /**
     * @brief Vráti MAC adresu
     * @return
     */
    std::string get_MAC_address();

    /**
     * @brief Nastaví MAC adresu na hodnotu new_MAC_address
     * @param new_MAC_address
     */
    void set_MAC_address(std::string new_MAC_address);

    /**
     * @brief Vráti IP adresu
     * @return
     */
    std::string get_IP_address();

    /**
     * @brief Nastaví hodnotu IP adresy na new_IP_address
     * @param new_IP_address
     */
    void set_IP_address(std::string new_IP_address);
};