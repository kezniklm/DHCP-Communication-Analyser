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
Arguments::Arguments() : is_interface(false), is_filename(false), file(nullptr)
{
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
            this->file = pcap_open_offline(argv[argument_number + NEXT_ARGUMENT], errbuf);
            if (this->file == nullptr)
            {
                error_exit("Chyba pri otváraní .pcap súboru %s\n", errbuf);
            }
            this->is_filename = true;
            argument_number++;
        }
        else if (!std::strcmp(argv[argument_number], "-i") && !this->is_interface)
        {
            this->is_another_argument(argv, argument_number);
            this->is_interface = true;
            this->interface = (std::string)argv[argument_number + NEXT_ARGUMENT];
            argument_number++;
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

        // Convert the integer to its binary representation
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
bool Arguments::is_prefix_in_vector(const IP_prefix &target)
{
    for (const IP_prefix &prefix_interator : this->IP_prefixes)
    {
        if (prefix_interator.prefix == target.prefix)
        {
            return true;
        }
    }
    return false;
}
