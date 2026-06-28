CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
LDFLAGS = -pthread
TARGET = arp_mitm

SRC = src/main.c src/net_interface.c src/host.c src/arp.c src/sniffer.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

run: all
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
