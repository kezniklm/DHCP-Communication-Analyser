/**
 * @file Utils.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia funkcií potrebných pre chod programu
 * @date 2023-11-20
 */

#include "Utils.hpp"

/**
 * @brief Rozdelí string na časti podľa delimetra
 * @param s String na rozdelenie
 * @param delimiter Delimeter
 * @return
 */
std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

/**
 * @brief Vráti MAC adresu odosieľateľa
 * @param header Pcap hlavička
 * @param buffer Paket
 */
std::string get_sender_mac_address(const pcap_pkthdr *header, const u_char *buffer)
{
    struct ether_header *eth_header = (struct ether_header *)buffer;

    unsigned char *sender_mac = eth_header->ether_shost;

    return format_MAC_stringstream(sender_mac);
}

/**
 * @brief Vráti MAC adresu prijímateľa
 * @param header Pcap hlavička
 * @param buffer Paket
 */
std::string get_receiver_mac_address(const pcap_pkthdr *header, const u_char *buffer)
{
    struct ether_header *eth_header = (struct ether_header *)buffer;

    unsigned char *receiver_mac = eth_header->ether_dhost;

    return format_MAC_stringstream(receiver_mac);
}

/**
 * @brief Sformátuje MAC adresu na tvar FF:FF:FF:FF:FF:FF
 * @param MAC_address MAC adresa v zlom formáte
 */
std::string format_MAC_stringstream(unsigned char *MAC_address)
{
    std::stringstream mac_stream;
    mac_stream << std::hex << std::setfill('0');
    mac_stream << std::setw(2) << std::uppercase << (int)MAC_address[0] << ":"
               << std::setw(2) << std::uppercase << (int)MAC_address[1] << ":"
               << std::setw(2) << std::uppercase << (int)MAC_address[2] << ":"
               << std::setw(2) << std::uppercase << (int)MAC_address[3] << ":"
               << std::setw(2) << std::uppercase << (int)MAC_address[4] << ":"
               << std::setw(2) << std::uppercase << (int)MAC_address[5];

    return mac_stream.str();
}

/**
 * @brief Prekonvertuje znaky MAC adresy na veľké písmená
 * @param macAddress
 */
std::string MAC_to_uppercase(const std::string &macAddress)
{
    std::string result = macAddress;

    for (char &c : result)
    {
        c = std::toupper(c);
    }

    return result;
}