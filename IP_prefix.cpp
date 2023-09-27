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
    this->usage = ((float)used / (float)this->maximum);
    return this->usage;
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

    return (availableAddresses - NETWORK_ADRESS - BROADCAST_ADRESS);
}