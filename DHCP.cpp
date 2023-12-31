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

/**
 * @brief Extrahuje ciaddr IP adresu z DHCP paketu
 * @param header Hlavička pcap
 * @param packet Paket
 * @return
 */
std::string DHCP::extract_ciaddr(const pcap_pkthdr *header, const u_char *packet)
{
    DHCP::packet *dhcp_header = (DHCP::packet *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    struct in_addr assigned_ip = dhcp_header->ciaddr;
    return inet_ntoa(assigned_ip);
}

/**
 * @brief Vráti destination IP z paketu
 * @param header Hlavička pcap
 * @param packet Paket
 * @return
 */
std::string DHCP::get_dest_IP(const pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    return dest_ip;
}

/**
 * @brief Extrahuje chaddr - MAC adresu z DHCP paketu
 * @param header Hlavička pcap
 * @param packet Paket
 * @return
 */
std::string DHCP::extract_chaddr(const pcap_pkthdr *header, const u_char *packet)
{
    DHCP::packet *dhcp_header = (DHCP::packet *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    std::string MAC_address = format_MAC_stringstream(dhcp_header->chaddr);
    return MAC_address;
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
    DHCP::packet *dhcp_header = (DHCP::packet *)(buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    u_char *options = (u_char *)dhcp_header + 240;
    int option_len = header->caplen - 240;

    for (int i = 0; i < option_len - 2;)
    {
        int option_code = options[i++];
        int option_length = options[i++];

        if (i + option_length > option_len)
        {
            return false;
        }

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
        this->is_DORA_continuous(get_sender_mac_address(header, buffer), this->Discover);
    }
    else if (this->is_message_of_type(header, buffer, this->Offer))
    {
        std::string MAC_address = get_receiver_mac_address(header, buffer);
        if (MAC_address == BROADCAST_MAC)
        {
            MAC_address = extract_chaddr(header, buffer);
        }
        this->search_MAC_and_modify_flag(MAC_address, this->Offer);
        this->is_DORA_continuous(MAC_address, this->Offer);
    }
    else if (this->is_message_of_type(header, buffer, this->Request))
    {
        if (!this->is_in_clients_without_ip(get_sender_mac_address(header, buffer)))
        {
            Negotiator negotiator(header, buffer);
            negotiator.has_discover = true;
            negotiator.has_offer = true;
            this->clients_without_ip.push_back(negotiator);
        }
        this->search_MAC_and_modify_flag(get_sender_mac_address(header, buffer), this->Request);
        this->add_requested_ip(header, buffer);
        this->is_DORA_continuous(get_sender_mac_address(header, buffer), this->Request);
    }
    else if (this->is_message_of_type(header, buffer, this->Acknowledgment))
    {
        std::string MAC_address = get_receiver_mac_address(header, buffer);
        if (MAC_address == BROADCAST_MAC)
        {
            MAC_address = extract_chaddr(header, buffer);
        }
        this->search_MAC_and_modify_flag(MAC_address, this->Acknowledgment);
        this->is_DORA_continuous(MAC_address, this->Acknowledgment);
        return this->is_negotiation_complete(MAC_address);
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
        if (iterator->get_IP_address() == IP_address && iterator->get_MAC_address() == MAC_address)
        {
            this->clients_without_ip.erase(iterator);
            return true;
        }
    }
    return false;
}

/**
 * @brief Vyhľadá clienta podľa MAC adresy vo vektori clients_without_ip
 * @param MAC_address
 * @return
 */
bool DHCP::is_in_clients_without_ip(std::string MAC_address)
{
    for (long unsigned int i = 0; i < this->clients_without_ip.size(); i++)
    {
        if (MAC_to_uppercase(this->clients_without_ip[i].get_MAC_address()) == MAC_to_uppercase(MAC_address))
        {
            return true;
        }
    }
    return false;
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
        if (MAC_to_uppercase(this->clients_without_ip[i].get_MAC_address()) == MAC_to_uppercase(MAC))
        {
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

    DHCP::packet *dhcp_header = (DHCP::packet *)(buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    u_char *options = (u_char *)dhcp_header + 240;
    int option_len = header->caplen - 240;

    for (int i = 0; i < option_len; i++)
    {
        int option_code = options[i];
        if (option_code == 50)
        {
            if (options[i + 1] == 4)
            {
                in_addr ip_addr;
                memcpy(&ip_addr, options + i + 2, sizeof(ip_addr));
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
