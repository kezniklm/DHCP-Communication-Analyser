/**
 * @file Arguments.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia spracovania argumentov programu dhcp-stats
 * @date 2023-11-20
 */

#include "Arguments.hpp"

/**
 * @brief Konštruktor triedy Arguments - inicializuje inštančné premenné
 */
Arguments::Arguments(WINDOW *prefix_window) : is_interface(false), is_filename(false), file(nullptr)
{
    this->prefix_window = prefix_window;
}

/**
 * @brief Deštruktor triedy Arguments - uvoľní pamäť alokovanú pre inštanciu triedy Arguments
 */
Arguments::~Arguments()
{
    this->IP_prefixes.clear();
}

/**
 * @brief Skontroluje a spracuje argumenty zadané na príkazový riadok
 * @param argc Počet argumentov programu
 * @param argv Argumenty programu
 */
void Arguments::check(int argc, char *argv[])
{
    if (!argv)
    {
        error_exit("Pole argumentov nemôže byť NULL\n");
    }

    for (int argument_number = FIRST_ARGUMENT; argument_number < argc; argument_number++)
    {
        if (!std::strcmp(argv[argument_number], "-r") && !this->is_filename)
        {
            this->is_another_argument(argv, argument_number);
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *file = pcap_open_offline(argv[argument_number + NEXT_ARGUMENT], errbuf);
            if (file == nullptr)
            {
                error_exit("Chyba pri otváraní .pcap súboru %s\n", errbuf);
            }
            this->is_filename = true;
            this->set_file(file);
            argument_number++;
        }
        else if (!std::strcmp(argv[argument_number], "-i") && !this->is_interface)
        {
            this->is_another_argument(argv, argument_number);
            this->is_interface = true;
            this->set_interface((std::string)argv[argument_number + NEXT_ARGUMENT]);
            argument_number++;
        }
        else if (!std::strcmp(argv[argument_number], "--ext"))
        {
            this->extensions = true;
        }
        else if (!std::strcmp(argv[argument_number], "--help") || !std::strcmp(argv[argument_number], "-h"))
        {
            printf("Názov:\n    dhcp-stats - analyzátor percentuálneho využitia sieťových prefixov\n\nPoužitie:\n  ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n\n  ./dhcp-stats --help \n\n  ./dhcp-stats -h \nPopis:\n    Sieťový analyzátor, ktorý umožňuje získanie percentuálneho využitia sieťových prefixov\n");
            std::exit(EXIT_SUCCESS);
        }
        else if (this->is_correct_prefix((std::string)argv[argument_number]))
        {
            if (this->is_prefix_in_vector((std::string)argv[argument_number]))
            {
                this->IP_prefixes.clear();
                this->IP_prefixes.~vector();
                error_exit("Prefix môže byť zadaný iba raz!\n");
            }
            IP_prefix prefix((std::string)argv[argument_number]);
            this->IP_prefixes.push_back(prefix);
            prefix.write_prefix(this->prefix_window, this->IP_prefixes.size());
        }
        else
        {
            error_exit("Chybný argument programu. Vyskúšajte ./dhcp-stats --help\n");
        }
    }
    if (this->is_interface && this->is_filename || !this->is_interface && !this->is_filename)
    {
        error_exit("Chybná kombinácia argumentov programu - je nutné použiť rozhranie alebo súbor\n");
    }

    if (this->IP_prefixes.empty())
    {
        error_exit("Chybná kombinácia argumentov programu - je nutné zadať aspoň jeden prefix\n");
    }
}

/**
 * @brief Skontroluje prítomnosť a korektnosť druhého argumentu po aktuálnom argumente
 * @param argv Vstupné argumenty
 * @param argument_number Spracovávaný argument
 */
void Arguments::is_another_argument(char *argv[], int argument_number)
{
    if (argv[argument_number + NEXT_ARGUMENT] != NULL)
    {
        if (argv[argument_number + NEXT_ARGUMENT][0] == '-')
            error_exit("Chybný argument programu\n");
    }
    else
    {
        error_exit("Chybný argument programu\n");
    }
}

/**
 * @brief Skontroluje korektnosť prefixu
 * @param prefix Prefix, ktorý sa má skontrolovať
 * @return
 */
bool Arguments::is_correct_prefix(std::string prefix)
{
    this->check_overlap(prefix);
    std::istringstream iss(prefix);
    std::string address;
    std::string mask;
    if (std::getline(iss, address, '/') && std::getline(iss, mask))
    {
        this->check_ip_format(address);
        this->check_mask(mask);
    }
    else
    {
        error_exit("Chybný argument programu\n");
    }

    return true;
}

/**
 * @brief Skontroluje, či sa jedná o adresu siete a nie rozhrania
 * @param prefix Prefix, ktorý sa má skontrolovať
 */
void Arguments::check_overlap(std::string prefix)
{
    std::string address = prefix.substr(0, prefix.find('/'));
    int network_bits = 0;
    try
    {
        network_bits = std::stoi(prefix.substr(prefix.find('/') + 1));
    }
    catch (const std::invalid_argument &e)
    {
        error_exit("Chybný argument programu\n");
    }
    catch (const std::out_of_range &e)
    {
        error_exit("Chybný argument programu\n");
    }
    std::istringstream iss(address);
    std::string octet;

    while (std::getline(iss, octet, '.'))
    {
        int number = std::stoi(octet);

        // Konvertuje integer na jeho binárnu repreyentáciu
        std::bitset<8> binary_representation(number);
        for (int i = binary_representation.size() - 1; i >= 0; --i)
        {
            if (network_bits-- <= 0 && binary_representation[i] != false)
            {
                error_exit("Prefix nie je správny - jedná sa o IP adresu rozhrania a nie siete\n");
            }
        }
    }
}

/**
 * @brief Skontroluje formát zadanej IPV4 adresy
 *
 * @param ip_address
 */
void Arguments::check_ip_format(std::string ip_address)
{
    if (ip_address.empty() || ip_address.length() > IP_LENGTH)
    {
        error_exit("IP adresa nemá požadovaný formát\n");
    }

    std::istringstream iss(ip_address);
    std::string octet;
    int octet_number = 0;
    while (std::getline(iss, octet, '.'))
    {
        if (octet_number > IP_OCTETS)
        {
            error_exit("IP adresa nemá požadovaný formát\n");
        }
        check_scope(octet, &octet_number);
    }
}

/**
 * @brief Skontroluje octety IPV4 adresy aby boli v intervale <0,255>
 *
 * @param octet
 * @param octet_num
 */
void Arguments::check_scope(std::string octet, int *octet_number)
{
    if (octet.empty() || !this->is_in_interval(octet, 0, 255))
    {
        error_exit("IP adresa nemá požadovaný formát\n");
    }

    (*octet_number)++;
}

/**
 * @brief Skontroluje počet bitov masky tak, aby bol v intervale <0,32>
 * @param mask Maska na skontrolovanie
 */
void Arguments::check_mask(std::string mask)
{
    if (mask.empty())
    {
        error_exit("Prefix nemá požadovaný formát\n");
    }

    if (!this->is_in_interval(mask, 0, 32))
    {
        error_exit("Prefix nemá požadovaný formát\n");
    }
}

/**
 * @brief Pridá klienta do vectoru prefixov
 * @param IP_address IP adresa klienta
 * @param MAC_address MAC adresa klienta
 */
void Arguments::add_client_to_prefix_vector(std::string IP_address, std::string MAC_address)
{
    for (IP_prefix prefix_interator : this->IP_prefixes)
    {
        if (prefix_interator.match_prefix(IP_address) && !prefix_interator.is_IP_in_vector(IP_address))
        {
            for (size_t i = 0; i < this->IP_prefixes.size(); ++i)
            {
                if (this->IP_prefixes[i].get_prefix() == prefix_interator.get_prefix() && !prefix_interator.is_network_broadcast_address(IP_address))
                {
                    this->IP_prefixes[i].add_IP_to_vector(IP_address, MAC_address);
                    if (this->IP_prefixes[i].get_maximum() == 0)
                    {
                        return;
                    }
                    int old_used = this->IP_prefixes[i].get_used();
                    this->IP_prefixes[i].set_used(++old_used);
                    this->IP_prefixes[i].calculate_usage(this->IP_prefixes[i].get_prefix());
                    this->IP_prefixes[i].write_prefix(this->prefix_window, i + 1);
                }
            }
        }
    }
}

/**
 * @brief Uvoľní klienta z vectoru prefixov
 * @param IP_address IP adresa klienta
 * @param MAC_address MAC adresa klienta
 */
void Arguments::release(std::string IP_address, std::string MAC_address)
{
    for (IP_prefix prefix_interator : this->IP_prefixes)
    {
        if (prefix_interator.match_prefix(IP_address) && prefix_interator.is_IP_in_vector(IP_address))
        {
            for (size_t i = 0; i < this->IP_prefixes.size(); ++i)
            {
                if (this->IP_prefixes[i].get_prefix() == prefix_interator.get_prefix() && !prefix_interator.is_network_broadcast_address(IP_address))
                {
                    if (this->IP_prefixes[i].get_maximum() == 0)
                    {
                        return;
                    }
                    this->IP_prefixes[i].delete_from_vector(IP_address, MAC_address);

                    int old_used = this->IP_prefixes[i].get_used();
                    this->IP_prefixes[i].set_used(--old_used);
                    this->IP_prefixes[i].calculate_usage(this->IP_prefixes[i].get_prefix());
                    this->IP_prefixes[i].write_prefix(this->prefix_window, i + 1);
                }
            }
        }
    }
}

/**
 * @brief Vráti interface
 * @return
 */
std::string Arguments::get_interface()
{
    return this->interface;
}

/**
 * @brief Nastaví interface na hodnotu new_interface
 * @param new_interface Nový interface
 */
void Arguments::set_interface(std::string new_interface)
{
    this->interface = new_interface;
}

/**
 * @brief Vráti file descriptor pcap súboru
 * @return
 */
pcap_t *Arguments::get_file()
{
    return this->file;
}

/**
 * @brief Nastaví file descriptor pcap súboru na new_file
 * @param new_file
 */
void Arguments::set_file(pcap_t *new_file)
{
    this->file = new_file;
}

/**
 * @brief Vráti prefix_window
 * @return
 */
WINDOW *Arguments::get_prefix_window()
{
    return this->prefix_window;
}

/**
 * @brief Nastaví prefix window na hodnotu new_prefix_window
 * @param new_prefix_window
 */
void Arguments::set_prefix_window(WINDOW *new_prefix_window)
{
    this->prefix_window = new_prefix_window;
}

/**
 * @brief Vráti vector IP prefixov
 * @return 
 */
std::vector<IP_prefix> Arguments::get_IP_prefixes()
{
    return this->IP_prefixes;
}

/**
 * @brief Kontroluje, či je číslo v zadanom intervale
 * @param to_check Číslo na skontrolovanie
 * @param start Začiatok intervalu
 * @param end Koniec intervalu
 * @return
 */
bool Arguments::is_in_interval(std::string to_check, int start, int end)
{
    try
    {
        int int_to_check = std::stoi(to_check);

        if (int_to_check < start || int_to_check > end)
        {
            return false;
        }
    }
    catch (const std::invalid_argument &e)
    {
        return false;
    }
    catch (const std::out_of_range &e)
    {
        return false;
    }
    return true;
}

/**
 * @brief Skontroluje, či zadaný prefix sa už nachádza vo vektore IP_prefixes
 * @param target Prefix, ktorý má byť skontrolovaný
 * @return
 */
bool Arguments::is_prefix_in_vector(IP_prefix target)
{
    for (IP_prefix prefix_interator : this->IP_prefixes)
    {
        if (prefix_interator.get_prefix() == target.get_prefix())
        {
            return true;
        }
    }
    return false;
}
