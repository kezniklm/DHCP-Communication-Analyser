/**
 * @file error.cpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Implementácia funkcií warning_msg() a error_exit() z error.hpp
 * @date 2023-11-20
 * Prelozene: GCC 11.3.0
 */

#include "error.hpp"

/**
 * @brief Vypíše text "CHYBA:..."
 */
void warning_msg(const char *fmt, ...)
{
    va_list arguments;
    va_start(arguments, fmt);

    std::cerr << "CHYBA:" << std::endl;
    vfprintf(stderr, fmt, arguments);

    va_end(arguments);
}

/**
 * @brief Vypíše text "CHYBA:..." a ukončí program s chybovým návratovým kódom 1
 */
void error_exit(const char *fmt, ...)
{
    va_list arguments;
    va_start(arguments, fmt);

    std::cerr << "CHYBA:" << std::endl;
    vfprintf(stderr, fmt, arguments);

    va_end(arguments);
    exit(EXIT_FAILURE);
}