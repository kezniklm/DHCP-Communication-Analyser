/**
 * @file IP_prefix.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia triedy IP_prefix pre spracovanie IP prefixov
 * @date 2023-11-20
 */

#include "IP_prefix.hpp"

/**
 * @brief Konštruktor triedy IP_prefix
 * @param prefix Prefix s overenou správnosťou
 */
IP_prefix::IP_prefix(std::string prefix)
{
    this->prefix = prefix;
    this->used = 0;
    this->usage = 0.0;
    this->maximum = this->calculate_maximum_usage(prefix);
}

/**
 * @brief Vypočíta percentuálne využitie prefixu
 * @param prefix Prefix s overenou správnosťou
 * @return Percentuálne využitie prefixu
 */
double IP_prefix::calculate_usage(std::string prefix)
{
    int used = this->IP_addresses.size();
    if (this->maximum == 0)
    {
        this->usage = 0.0;
    }
    else
    {
        this->usage = ((float)used / (float)this->maximum) * 100;
    }

    return this->usage * 100;
}

/**
 * @brief Pridá IP adresu do vektoru IP_adresses
 * @param IP_address IP adresa na pridanie
 */
void IP_prefix::add_IP_to_vector(std::string IP_address)
{
    if (!this->is_IP_in_vector(IP_address))
    {
        this->IP_addresses.push_back(IP_address);
    }
}

/**
 * @brief Odstráni IP adresu z vektoru IP_adresses
 * @param IP_address IP adresa na vymazanie
 */
void IP_prefix::delete_IP_from_vector(std::string IP_address)
{
    if (this->is_IP_in_vector(IP_address))
    {
        for (auto IP_address_interator = IP_addresses.begin(); IP_address_interator != IP_addresses.end(); ++IP_address_interator)
        {
            if (*IP_address_interator == IP_address)
            {
                this->IP_addresses.erase(IP_address_interator);
                break;
            }
        }
    }
    else
    {
        error_exit("Je možné vymazávať iba IP adresy nachádzajúce sa vo vectore IP_adresses\n");
    }
}

bool IP_prefix::match_prefix(const std::string &ip)
{
    // Split the prefix into address and network bits
    std::string address = prefix.substr(0, prefix.find('/'));
    int network_bits = std::stoi(prefix.substr(prefix.find('/') + 1));

    // printf("%s,%s", ip.c_str(), prefix.c_str());
    // fflush(stdout);

    // Split the IP address into octets
    std::vector<int> ip_octets;
    std::stringstream ss(ip);
    std::string octet;
    while (getline(ss, octet, '.'))
    {
        ip_octets.push_back(std::stoi(octet));
    }

    // Split the prefix address into octets
    std::vector<int> prefix_octets;
    std::stringstream ss2(address);
    while (getline(ss2, octet, '.'))
    {
        prefix_octets.push_back(std::stoi(octet));
    }

    // Compare octets up to the network_bits
    for (int i = 0; i < network_bits / 8; ++i)
    {
        if (ip_octets[i] != prefix_octets[i])
        {
            return false;
        }
    }

    // If network_bits is not a multiple of 8, compare the remaining bits
    if (network_bits % 8 != 0)
    {
        int mask = 0xFF << (8 - (network_bits % 8));
        if ((ip_octets[network_bits / 8] & mask) != (prefix_octets[network_bits / 8] & mask))
        {
            return false;
        }
    }

    return true;
}

/**
 * @brief Zistí, či sa IP adresa nachádza vo vektore IP_adresses
 * @param IP_address IP adresa, ktorá sa má nájsť
 * @return
 */
bool IP_prefix::is_IP_in_vector(std::string IP_address)
{
    for (const std::string IP_address_interator : this->IP_addresses)
    {
        if (IP_address_interator == IP_address)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Vypočíta maximálny počet použiteľných IP adries v rámci prefixu
 * @param prefix Prefix s overenou správnosťou
 * @return Maximálne počet použiteľných IP adries v rámci prefixu
 */
int IP_prefix::calculate_maximum_usage(std::string prefix)
{
    std::string ipAddress = prefix.substr(0, prefix.find('/'));
    int prefixLength;
    std::istringstream(prefix.substr(prefix.find('/') + 1)) >> prefixLength;

    // Prevod IPv4 adresy na jej binárnu reprezentáciu
    std::string binaryIpAddress = "";
    std::string octet;
    std::istringstream octetStream(ipAddress);
    while (std::getline(octetStream, octet, '.'))
    {
        int value = std::stoi(octet);
        binaryIpAddress += std::bitset<8>(value).to_string();
    }

    // Výpočet dostupných adries
    int availableAddresses = 1 << (32 - prefixLength);
    if ((availableAddresses - NETWORK_ADRESS - BROADCAST_ADRESS) == 0)
    {
        warning_msg("Prefix nemá voľné žiadne adresy!");
        return 0;
    }
    else
    {
        return (availableAddresses - NETWORK_ADRESS - BROADCAST_ADRESS);
    }
}

void IP_prefix::write_prefix(WINDOW *prefix_window, int number_of_prefix)
{
    mvwprintw(prefix_window, number_of_prefix, 1, "%s", this->prefix.c_str());
    mvwprintw(prefix_window, number_of_prefix, 20, "%d", this->maximum);
    mvwprintw(prefix_window, number_of_prefix, 40, "%d", this->used);
    mvwprintw(prefix_window, number_of_prefix, 60, "%.2f%%", this->usage);
    wnoutrefresh(prefix_window);
    doupdate();
}

bool IP_prefix::is_network_broadcast_address(std::string IP_address)
{
    // Split the IP address and prefix into components
    std::vector<std::string> ipParts = split(IP_address, '.');
    std::vector<std::string> prefixParts = split(this->prefix, '/');
    // Ensure that both the IP and prefix have valid components
    if (ipParts.size() != 4 || prefixParts.size() != 2)
    {
        return false;
    }

    // Extract the IP address and prefix length
    std::string ipAddress = ipParts[0] + "." + ipParts[1] + "." + ipParts[2] + "." + ipParts[3];
    int prefixLength = std::stoi(prefixParts[1]);

    // Calculate the network address and broadcast address based on the prefix
    int subnetMask = (0xFFFFFFFF << (32 - prefixLength));
    int networkAddress = (std::stoi(ipParts[0]) << 24) | (std::stoi(ipParts[1]) << 16) | (std::stoi(ipParts[2]) << 8) | std::stoi(ipParts[3]);
    networkAddress = networkAddress & subnetMask; // Corrected network address calculation
    int broadcastAddress = networkAddress | (~subnetMask);

    // Convert the calculated network and broadcast addresses to string format
    std::string networkAddressStr = std::to_string((networkAddress >> 24) & 0xFF) + "." +
                                    std::to_string((networkAddress >> 16) & 0xFF) + "." +
                                    std::to_string((networkAddress >> 8) & 0xFF) + "." +
                                    std::to_string(networkAddress & 0xFF);

    std::string broadcastAddressStr = std::to_string((broadcastAddress >> 24) & 0xFF) + "." +
                                      std::to_string((broadcastAddress >> 16) & 0xFF) + "." +
                                      std::to_string((broadcastAddress >> 8) & 0xFF) + "." +
                                      std::to_string(broadcastAddress & 0xFF);

    // Check if the IP address matches either the network or broadcast address
    return (ipAddress == networkAddressStr) || (ipAddress == broadcastAddressStr);
}

// Function to split a string by a delimiter and return a vector of substrings - upratať potom
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