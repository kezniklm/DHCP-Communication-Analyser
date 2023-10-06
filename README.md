# DHCP Communication Analyser - DHCP Stats

*Autor:* Matej Keznikl\
*Login:* xkezni01\
*Dátum vytvorenia:* 6.10.2023

## Popis

Cieľom bolo vytvoriť sieťový analyzátor ktorý umožňuje monitorovať sieťovú prevádzku DHCP serveru a získavať štatistiky o vyťažení sieťových prefixov na základe alokovaných IP adries. Aplikácia môže pracovať v reálnom čase na sieťovom rozhraní alebo analyzovať DHCP prevádzku z pcap súborov.\

### Funkcie

Aplikácia podporuje nasledujúce funkcie:
- Monitorovanie DHCP prevádzky na sieťovom rozhraní.
- Analýzu pcap súborov obsahujúcich DHCP prevádzku.
- Sledovanie viacerých sieťových prefixov, vrátane prekryvajúcich sa prefixov.
- Výpočet vyťaženia sieťových prefixov na základe alokovaných adries.
- V prípade vyťaženia sieťového prefixu nad 50% alokovaných adries zápis záznamu do syslogu.

### Rozšírenia
- Podpora uvoľňovania adries správou od klienta - DHCPRELEASE
- Dôrazné overovanie správnosti prefixu, vrátane kontroly prekryvu adresy siete a adresy rozhrania

### Implementácia
Sieťová aplikácia dhcp-stats je implementovaná v jazyku C++, revízia C++20 (ISO/IEC 14882:2020). Doporučuje sa prekladač g++ verzie 11.4.0 a jeho novšie vydania.

## Spustenie

```bash
./dhcp-stats [-r <filename>] [-i <interface-name>]  [--ext] <ip-prefix> [ <ip-prefix> [ ... ] ]
    -r <filename> - štatistika bude vytvorená z pcap súborov
    -i <interface> - rozhranie, ktoré bude program analyzovať
    --ext - rozšírenie umožňujúce podporu uvoľňovania adries správou od klienta - DHCPRELEASE 
    <ip-prefix> - rozsah siete, pre ktorý sa bude generovať štatistika
```

## Zoznam súborov
- Arguments.cpp
- Arguments.hpp
- dhcp-stats.cpp
- dhcp-stats.hpp
- DHCP.cpp
- DHCP.hpp
- error.cpp
- error.hpp
- IP_prefix.cpp
- IP_prefix.hpp
- Makefile
- test.py
- manual.pdf
- dhcp-stats.1
