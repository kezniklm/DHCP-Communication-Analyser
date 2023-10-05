/**
 * @file DHCP.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia operácií s DHCP paketmi
 * @date 2023-11-20
 */

#include "DHCP.hpp"

/**
 * @brief Konštruktor triedy DHCP
 */
DHCP::DHCP()
{
}

/**
 * @brief Extrahuje pridelenú IP adresu z DHCP paketu
 * @param header Hlavička pcap
 * @param packet Paket
 * @return
 */
std::string DHCP::extract_yiaddr(const struct pcap_pkthdr *header, const u_char *packet)
{
    DHCP::packet *dhcp_header = (DHCP::packet *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    struct in_addr assigned_ip = dhcp_header->yiaddr;
    return inet_ntoa(assigned_ip);
}

std::string DHCP::extract_ciaddr(const pcap_pkthdr *header, const u_char *packet)
{
    DHCP::packet *dhcp_header = (DHCP::packet *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    struct in_addr assigned_ip = dhcp_header->ciaddr;
    return inet_ntoa(assigned_ip);
}

/**
 * @brief Overí, či je správa typu type
 * @param header Hlavička pcap
 * @param buffer Paket
 * @param type Typ správy
 * @return
 */
bool DHCP::is_message_of_type(const struct pcap_pkthdr *header, const u_char *buffer, const int type)
{
    u_char *options = (u_char *)buffer + 240; // DHCP options start at byte 240
    int option_len = header->caplen - 240;

    for (int i = 0; i < option_len;)
    {
        int option_code = options[i++];
        int option_length = options[i++];
        if (option_code == 53 && option_length == 1)
        {
            int dhcp_msg_type = options[i++];
            if (dhcp_msg_type == type)
            {
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief Uvoľní pridelenú IP adresu v prípade správy DHCP RELEASE
 * @param header Hlavička pcap
 * @param buffer Paket
 * @return
 */
bool DHCP::is_release(const pcap_pkthdr *header, const u_char *buffer)
{
    return this->is_message_of_type(header, buffer, this->Release);
}

/**
 * @brief Overí, či DHCP "handshake" je v korektnom poradí
 * @param header pcap
 * @param buffer Paket
 * @return
 */
bool DHCP::verify_dhcp_negotiation(const pcap_pkthdr *header, const u_char *buffer)
{
    if (this->is_message_of_type(header, buffer, this->Discover))
    {
        Negotiator negotiator(header, buffer);
        this->clients_without_ip.push_back(negotiator);
        this->is_DORA_continuous(get_receiver_mac_address(header, buffer), this->Discover);
    }
    else if (this->is_message_of_type(header, buffer, this->Offer))
    {
        this->search_MAC_and_modify_flag(get_receiver_mac_address(header, buffer), this->Offer);
        this->is_DORA_continuous(get_receiver_mac_address(header, buffer), this->Offer);
    }
    else if (this->is_message_of_type(header, buffer, this->Request))
    {
        this->search_MAC_and_modify_flag(get_sender_mac_address(header, buffer), this->Request);
        this->add_requested_ip(header, buffer);
        this->is_DORA_continuous(get_receiver_mac_address(header, buffer), this->Request);
    }
    else if (this->is_message_of_type(header, buffer, this->Acknowledgment))
    {
        this->search_MAC_and_modify_flag(get_receiver_mac_address(header, buffer), this->Acknowledgment);
        this->is_DORA_continuous(get_receiver_mac_address(header, buffer), this->Acknowledgment);
        return this->is_negotiation_complete(get_receiver_mac_address(header, buffer));
    }
    return false;
}

/**
 * @brief Overí, či poradie Discovery, Offer, Request a Acknowledge správ je korektné
 * @param MAC MAC adresa clienta
 * @param type Typ správy na overenie
 */
void DHCP::is_DORA_continuous(const std::string MAC, const int type)
{
    for (long unsigned int i = 0; i < this->clients_without_ip.size(); i++)
    {
        if (MAC_to_uppercase(this->clients_without_ip[i].get_MAC_address()) == MAC_to_uppercase(MAC))
        {
            if (type == this->Discover)
            {
                if (!(this->clients_without_ip[i].has_offer || this->clients_without_ip[i].has_request || this->clients_without_ip[i].has_ack))
                {
                    this->clients_without_ip[i].has_ack = false;
                    this->clients_without_ip[i].has_offer = false;
                    this->clients_without_ip[i].has_request = false;
                }
            }
            else if (type == this->Offer)
            {
                if (!(this->clients_without_ip[i].has_request || this->clients_without_ip[i].has_ack))
                {
                    this->clients_without_ip[i].has_ack = false;
                    this->clients_without_ip[i].has_request = false;
                }
            }
            else if (type == this->Request)
            {
                if (!(this->clients_without_ip[i].has_ack))
                {
                    this->clients_without_ip[i].has_ack = false;
                }
            }
            else
            {
                return;
            }
        }
    }
}

/**
 * @brief Skontroluje, či pár IP:MAC adresa sedí s tým, čo bolo poslané v REQUEST message
 * @param IP_address IP adresa
 * @param MAC_address MAC adresa
 * @return
 */
bool DHCP::check_MAC_IP_pair(std::string IP_address, std::string MAC_address)
{
    for (auto iterator = this->clients_without_ip.begin(); iterator < this->clients_without_ip.end(); iterator++)
    {
        if (!(iterator->get_IP_address() == IP_address && iterator->get_MAC_address() == MAC_address))
        {
            this->clients_without_ip.erase(iterator);
            return false;
        }
    }
    return true;
}

/**
 * @brief Skontroluje, či DORA proces prebehol úspešne
 * @param MAC MAC adresa zariadenia
 * @return
 */
bool DHCP::is_negotiation_complete(std::string MAC)
{
    for (long unsigned int i = 0; i < this->clients_without_ip.size(); i++)
    {
        // printf("%s a %s", MAC_to_uppercase(this->clients_without_ip[i].get_MAC_address()).c_str(), MAC_to_uppercase(MAC).c_str());
        // fflush(stdout);
        if (MAC_to_uppercase(this->clients_without_ip[i].get_MAC_address()) == MAC_to_uppercase(MAC))
        {
            // printf("%d,%d,%d,%d",this->clients_without_ip[i].has_discover,this->clients_without_ip[i].has_offer,this->clients_without_ip[i].has_request,this->clients_without_ip[i].has_ack);
            // fflush(stdout);
            if (!this->clients_without_ip[i].has_discover || !this->clients_without_ip[i].has_offer || !this->clients_without_ip[i].has_request || !this->clients_without_ip[i].has_ack)
            {
                return false;
            }
            return true;
        }
    }
    return false;
}

/**
 * @brief Pridá do zoznamu clients_without_ip klientovi žiadanú IP adresu
 * @param header Pcap hlavička
 * @param buffer Paket
 */
void DHCP::add_requested_ip(const pcap_pkthdr *header, const u_char *buffer)
{
    if (get_receiver_mac_address(header, buffer) != BROADCAST_MAC)
    {
        return;
    }

    u_char *options = (u_char *)buffer + 240; // DHCP options start at byte 240
    int option_len = header->caplen - 240;

    for (int i = 0; i < option_len; i++)
    {
        int option_code = options[i];
        if (option_code == 50)
        {
            in_addr ip_addr;
            memcpy(&ip_addr, options + i + 2, sizeof(ip_addr));

            // Convert the binary IP address to a human-readable string
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

            for (long unsigned int i = 0; i < this->clients_without_ip.size(); i++)
            {
                if (this->clients_without_ip[i].get_MAC_address() == get_sender_mac_address(header, buffer))
                {
                    this->clients_without_ip[i].set_IP_address(ip_str);
                }
            }

            return;
        }
    }
}

/**
 * @brief Nájde klienta s MAC adresou a podľa typu nastaví, aký typ správy aktuálne klient má
 * @param MAC MAC adresa klienta
 * @param type Typ správy
 */
void DHCP::search_MAC_and_modify_flag(const std::string MAC, const int type)
{
    for (long unsigned int i = 0; i < this->clients_without_ip.size(); i++)
    {
        if (MAC_to_uppercase(this->clients_without_ip[i].get_MAC_address()) == MAC_to_uppercase(MAC))
        {
            if (type == this->Discover)
            {
                this->clients_without_ip[i].has_discover = true;
            }
            else if (type == this->Offer)
            {
                this->clients_without_ip[i].has_offer = true;
            }
            else if (type == this->Request)
            {
                this->clients_without_ip[i].has_request = true;
            }
            else if (type == this->Acknowledgment)
            {
                this->clients_without_ip[i].has_ack = true;
            }
        }
    }
}

/**
 * @brief Konštruktor triedy Negotiator
 * @return
 */
Negotiator::Negotiator(const pcap_pkthdr *header, const u_char *buffer)
{
    this->MAC_adress = get_sender_mac_address(header, buffer);
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
