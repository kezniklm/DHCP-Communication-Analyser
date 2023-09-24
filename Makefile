#Makefile
#Riešenie ISA-projekt
#Datum odovzdania: 20.11.2023
#Autor: Matej Keznikl
#Fakulta: Fakulta informačných technológií VUT v Brne (FIT VUT)
#Prelozene: GCC 11.3.0

CC = g++
CFLAGS = -std=c++20 -pedantic -Wextra -Werror -g -fcommon -D_DEFAULT_SOURCE -lpcap 

.PHONY: error.o args.o dhcp-stats.o dhcp-stats zip clean

dhcp-stats: error.o args.o dhcp-stats.o
	$(CC) $(CFLAGS) error.o args.o dhcp-stats.o -o dhcp-stats -lpcap 

error.o: error.h error.cpp 
	$(CC) $(CFLAGS) -c error.cpp -o error.o

args.o: args.h args.cpp
	$(CC) $(CFLAGS) -c args.cpp -o args.o

dhcp-stats.o: dhcp-stats.h dhcp-stats.cpp
	$(CC) $(CFLAGS) -c dhcp-stats.cpp -o dhcp-stats.o

zip:
	zip -r xkezni01 * .gitignore
	
clean:
	rm -f dhcp-stats
	rm -f xkezni01.zip
	rm -f *.o 
	