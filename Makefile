#Makefile
#Riešenie ISA-projekt
#Datum odovzdania: 20.11.2023
#Autor: Matej Keznikl
#Fakulta: Fakulta informačných technológií VUT v Brne (FIT VUT)
#Prelozene: GCC 11.3.0

CC = g++
CFLAGS = -std=c++20 -pedantic -Wextra -Werror -g -fcommon -lpcap 

.PHONY: error.o Arguments.o dhcp-stats.o dhcp-stats zip clean

dhcp-stats: error.o IP_prefix.o Arguments.o DHCP.o dhcp-stats.o
	$(CC) $(CFLAGS) error.o IP_prefix.o Arguments.o DHCP.o dhcp-stats.o -o dhcp-stats -lpcap -lncurses

error.o: error.hpp error.cpp 
	$(CC) $(CFLAGS) -c error.cpp -o error.o

Arguments.o: Arguments.hpp Arguments.cpp
	$(CC) $(CFLAGS) -c Arguments.cpp -o Arguments.o

IP_prefix.o: IP_prefix.hpp IP_prefix.cpp 
	$(CC) $(CFLAGS) -c IP_prefix.cpp -o IP_prefix.o

DHCP.o: DHCP.hpp DHCP.cpp 
	$(CC) $(CFLAGS) -c DHCP.cpp -o DHCP.o

dhcp-stats.o: dhcp-stats.hpp dhcp-stats.cpp
	$(CC) $(CFLAGS) -c dhcp-stats.cpp -o dhcp-stats.o

zip:
	zip -r xkezni01 * .gitignore
	
clean:
	rm -f dhcp-stats
	rm -f xkezni01.zip
	rm -f *.o 
	