/**
 * @file args.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia spracovania argumentov programu dhcp-stats
 * @date 2023-11-20
 */

#include "args.h"

Arguments::Arguments() : is_interface(false), is_filename(false), prefix(nullptr)
{
}

void Arguments::check(int argc, char *argv[])
{
    if (!argv)
    {
        error_exit("Pole argumentov nemôže byť NULL");
    }

    for (int i = FIRST_ARGUMENT; i < argc; i++)
    {
        if (argv[i] == "-r")
        {

        }
        else if (argv[i] == "-i")
        {
            /* code */
        }
        else if (argv[i] == "--help" || argv[i] == "-h")
        {
            /* code */
        }
        else if (argv[i] != nullptr)
        {
            /* code */
        }
        else
        {
            error_exit("Chybný argument programu. Vyskúšajte ./dhcp-stats --help\n");
        }     
    }
}