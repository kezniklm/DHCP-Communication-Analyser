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
 * @return Percentuálne využitie prefixu
 */
double IP_prefix::calculate_usage()
{
    int used = this->Clients.size();
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
 * @param MAC_address MAC adresa na pridanie
 */
void IP_prefix::add_IP_to_vector(std::string IP_address, std::string MAC_address)
{
    if (!this->is_IP_in_vector(IP_address))
    {
        Client client(IP_address, MAC_address);
        this->Clients.push_back(client);
    }
}

/**
 * @brief Odstráni IP adresu z vektoru IP_adresses
 * @param IP_address IP adresa na vymazanie
 * @param MAC_address MAC adresa na vymazanie
 */
void IP_prefix::delete_from_vector(std::string IP_address, std::string MAC_address)
{
    if (this->is_IP_in_vector(IP_address))
    {
        for (auto clients_interator = Clients.begin(); clients_interator != Clients.end(); ++clients_interator)
        {
            if (clients_interator->get_IP_address() == IP_address && clients_interator->get_MAC_address() == MAC_address)
            {
                this->Clients.erase(clients_interator);
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
 * @brief V prípade, že počet alokovaných adries v prefixe prekročí 50%, zaloguje túto informáciu cez standardní syslog mechanismus do logu
 */
void IP_prefix::has_50_percent()
{
    if (this->get_usage() > 50.00)
    {
        syslog(LOG_WARNING, "prefix %s exceeded 50%% of allocations.", this->get_prefix().c_str());
    }
}

/**
 * @brief Vráti prefix
 * @return
 */
std::string IP_prefix::get_prefix()
{
    return this->prefix;
}

/**
 * @brief Nastaví prefix na honotu new_prefix
 * @param new_prefix
 */
void IP_prefix::set_prefix(std::string new_prefix)
{
    this->prefix = new_prefix;
}

/**
 * @brief Vráti maximum
 * @return
 */
int IP_prefix::get_maximum()
{
    return this->maximum;
}

/**
 * @brief Nastaví maximum na hodnotu new_maximum
 * @param new_maximum
 */
void IP_prefix::set_maximum(int new_maximum)
{
    this->maximum = new_maximum;
}

/**
 * @brief Vráti hodnotu used
 * @return
 */
int IP_prefix::get_used()
{
    return this->used;
}

/**
 * @brief Nastaví hodnotu used na hodnotu new_used
 * @param new_used
 */
void IP_prefix::set_used(int new_used)
{
    this->used = new_used;
}

/**
 * @brief Vráti usage
 * @return
 */
double IP_prefix::get_usage()
{
    return this->usage;
}

/**
 * @brief Nastaví usage na hodnotu new_usage
 * @param new_usage
 */
void IP_prefix::set_usage(double new_usage)
{
    this->usage = new_usage;
}

/**
 * @brief Vráti vektor clientov pre daný prefix
 * @return
 */
std::vector<Client> IP_prefix::get_clients_vector()
{
    return this->Clients;
}

/**
 * @brief Zisti či IP adresa patrí do daného prefixu
 * @param IP_address IP adresa
 * @return
 */
bool IP_prefix::match_prefix(const std::string &IP_address)
{
    // Rozdelenie prefixu na adresu siete a počet bitov masky
    std::string address = prefix.substr(0, prefix.find('/'));
    int network_bits = std::stoi(prefix.substr(prefix.find('/') + 1));

    // Rozdelenie IP adresy na oktety
    std::vector<int> ip_octets;
    std::stringstream ss(IP_address);
    std::string octet;
    while (getline(ss, octet, '.'))
    {
        ip_octets.push_back(std::stoi(octet));
    }

    // Rozdelenie adresy siete na oktety
    std::vector<int> prefix_octets;
    std::stringstream ss2(address);
    while (getline(ss2, octet, '.'))
    {
        prefix_octets.push_back(std::stoi(octet));
    }

    // Porovnanie adries zľava podľa počtu bitov masky
    for (int i = 0; i < network_bits / 8; ++i)
    {
        if (ip_octets[i] != prefix_octets[i])
        {
            return false;
        }
    }

    // Pokiaľ počet bitov je menej ako 8
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
    for (Client Clients_interator : this->Clients)
    {
        if (Clients_interator.get_IP_address() == IP_address)
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

/**
 * @brief Vypíše, prípadne prepíše výstupné okno
 * @param prefix_window Okno ncurses
 * @param number_of_prefix Poradie prefixu
 */
void IP_prefix::write_prefix(WINDOW *prefix_window, int number_of_prefix)
{
    mvwprintw(prefix_window, number_of_prefix, 1, "%s", this->prefix.c_str());
    mvwprintw(prefix_window, number_of_prefix, 20, "%d", this->maximum);
    mvwprintw(prefix_window, number_of_prefix, 40, "%d", this->used);
    mvwprintw(prefix_window, number_of_prefix, 60, "%.2f%%", this->usage);
    wnoutrefresh(prefix_window);
    doupdate();
}

/**
 * @brief Zistí, či sa nejedná o IP adresu siete alebo broadcastovú adresu siete
 * @param IP_address IP adresa
 * @return
 */
bool IP_prefix::is_network_broadcast_address(std::string IP_address)
{
    // Rozdelí IP adresu na časti
    std::vector<std::string> ipParts = split(IP_address, '.');
    std::vector<std::string> prefixParts = split(this->prefix, '/');

    // Kontrola, že IP a prefix majú daný poćet častí
    if (ipParts.size() != 4 || prefixParts.size() != 2)
    {
        return false;
    }

    // Extrahovanie IP adresy siete a  dĺžky prefixu
    std::string ipAddress = ipParts[0] + "." + ipParts[1] + "." + ipParts[2] + "." + ipParts[3];
    int prefixLength = std::stoi(prefixParts[1]);

    // Vypočítanie adresy siete a broadcastu podľa prefixu
    int subnetMask = (0xFFFFFFFF << (32 - prefixLength));
    int networkAddress = (std::stoi(ipParts[0]) << 24) | (std::stoi(ipParts[1]) << 16) | (std::stoi(ipParts[2]) << 8) | std::stoi(ipParts[3]);
    networkAddress = networkAddress & subnetMask;
    int broadcastAddress = networkAddress | (~subnetMask);

    // Prevedenie adresy na string
    std::string networkAddressStr = std::to_string((networkAddress >> 24) & 0xFF) + "." +
                                    std::to_string((networkAddress >> 16) & 0xFF) + "." +
                                    std::to_string((networkAddress >> 8) & 0xFF) + "." +
                                    std::to_string(networkAddress & 0xFF);

    std::string broadcastAddressStr = std::to_string((broadcastAddress >> 24) & 0xFF) + "." +
                                      std::to_string((broadcastAddress >> 16) & 0xFF) + "." +
                                      std::to_string((broadcastAddress >> 8) & 0xFF) + "." +
                                      std::to_string(broadcastAddress & 0xFF);

    // Pokiaľ sa nejedná o broadcast alebo adresu siete, vracia false
    return (ipAddress == networkAddressStr) || (ipAddress == broadcastAddressStr);
}
