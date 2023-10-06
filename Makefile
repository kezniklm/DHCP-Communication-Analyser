#Makefile
#Riešenie ISA-projekt
#Datum odovzdania: 20.11.2023
#Autor: Matej Keznikl
#Fakulta: Fakulta informačných technológií VUT v Brne (FIT VUT)
#Prelozene: GCC 11.3.0

CC = g++
CFLAGS = -std=c++20 -pedantic -Wextra -Werror -g -fcommon -lpcap 

.PHONY: error.o Arguments.o dhcp-stats.o dhcp-stats zip clean

dhcp-stats: Error.o Negotiator.o Utils.o Clients.o IP_prefix.o Arguments.o DHCP.o dhcp-stats.o
	$(CC) $(CFLAGS) Error.o Clients.o Utils.o Negotiator.o IP_prefix.o Arguments.o DHCP.o dhcp-stats.o -o dhcp-stats -lpcap -lncurses

Error.o: Error.hpp Error.cpp 
	$(CC) $(CFLAGS) -c Error.cpp -o Error.o

Arguments.o: Arguments.hpp Arguments.cpp
	$(CC) $(CFLAGS) -c Arguments.cpp -o Arguments.o

Clients.o: Clients.hpp Clients.cpp
	$(CC) $(CFLAGS) -c Clients.cpp -o Clients.o

IP_prefix.o: IP_prefix.hpp IP_prefix.cpp 
	$(CC) $(CFLAGS) -c IP_prefix.cpp -o IP_prefix.o

DHCP.o: DHCP.hpp DHCP.cpp 
	$(CC) $(CFLAGS) -c DHCP.cpp -o DHCP.o

Negotiator.o: Negotiator.hpp Negotiator.cpp 
	$(CC) $(CFLAGS) -c Negotiator.cpp -o Negotiator.o

Utils.o: Utils.hpp Utils.cpp 
	$(CC) $(CFLAGS) -c Utils.cpp -o Utils.o

dhcp-stats.o: dhcp-stats.hpp dhcp-stats.cpp
	$(CC) $(CFLAGS) -c dhcp-stats.cpp -o dhcp-stats.o

zip:
	zip -r xkezni01 * .gitignore
	
clean:
	rm -f dhcp-stats
	rm -f xkezni01.zip
	rm -f *.o 
	