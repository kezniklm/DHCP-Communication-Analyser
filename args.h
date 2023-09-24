/**
 * @file args.h
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor pre spracovanie argumentov programu dhcp-stats
 * @date 2023-11-20
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "error.h"

#define FIRST_ARGUMENT 1

class Arguments
{
public:
    Arguments();
    void check(int argc, char *argv[]);

private:
    bool is_interface;
    std::string interface;
    bool is_filename;
    std::string filename;
    struct IP_prefix *prefix;
};

struct IP_prefix
{
    std::string prefix;
    int maximum;
    int used;
    struct IP_prefix *next_prefix;
};
