/**
 * @file Utils.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor funkcií potrebných pre chod programu
 * @date 2023-11-20
 */

#include <string>
#include <vector>
#include <pcap.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <netinet/if_ether.h>

/**
 * @brief Rozdelí string na časti podľa delimetra
 * @param s String na rozdelenie
 * @param delimiter Delimeter
 * @return
 */
std::vector<std::string> split(const std::string &s, char delimiter);

/**
 * @brief Vráti MAC adresu odosieľateľa
 * @param header Pcap hlavička
 * @param buffer Paket
 */
std::string get_sender_mac_address(const pcap_pkthdr *header, const u_char *buffer);

/**
 * @brief Vráti MAC adresu prijímateľa
 * @param header Pcap hlavička
 * @param buffer Paket
 */
std::string get_receiver_mac_address(const pcap_pkthdr *header, const u_char *buffer);

/**
 * @brief Sformátuje MAC adresu na tvar FF:FF:FF:FF:FF:FF
 * @param MAC_address MAC adresa v zlom formáte
 */
std::string format_MAC_stringstream(unsigned char *MAC_address);

/**
 * @brief Prekonvertuje znaky MAC adresy na veľké písmená
 * @param macAddress
 */
std::string MAC_to_uppercase(const std::string &macAddress);