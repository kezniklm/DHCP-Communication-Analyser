/**
 * @file error.hpp
 * @author Matej Keznikl (xkezni01@stud.fit.vutbr.cz)
 * @brief Hlavičkový súbor obsahujúci prototypy funkcíí z error.cpp
 * @date 2023-11-20
 * Prelozene: GCC 11.3.0
 */

#pragma once

#include <iostream>
#include <cstdlib>
#include <cstdarg>

/**
 * @brief Vypíše text "CHYBA:..."
 */
void warning_msg(const char *fmt, ...);

/**
 * @brief Vypíše text "CHYBA:..." a ukončí program s chybovým návratovým kódom 1
 */
void error_exit(const char *fmt, ...);
