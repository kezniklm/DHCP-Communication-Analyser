/**
 * @file Clients.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor triedy Clients
 * @date 2023-11-20
 */

#include <string>

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