# Projekt: Nástroje monitorující a generující zprávy jednoduchých distance-vector protokolů
# Autor:   Pavel Chlubna
# Datum:   Listopad, 2018

CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -Werror -pedantic
LDFLAGS = -lpcap
FILES = myripsniffer.c myripresponse.c

all: myripsniffer myripresponse



myripsniffer: myripsniffer.c
	$(CC) $(CFLAGS) -o $@ myripsniffer.c $(LDFLAGS)


myripresponse: myripresponse.c
	$(CC) $(CFLAGS) -o $@ myripresponse.c $(LDFLAGS)

clean:
	rm -f *.o *.out myripsniffer myripresponse *~
