#ifndef NET_INTERFACE_H
#define NET_INTERFACE_H

#include <arpa/inet.h>

typedef struct {
    char name[64];
    char mask[16];
    char mac[18];
    char ip[16];
} NetInterface;

void get_local_ip(char ip[INET_ADDRSTRLEN]);
void get_mac_address(const char *ifname, char mac[18]);
NetInterface get_net_interface(void);
void print_interface(NetInterface netint);

#endif
