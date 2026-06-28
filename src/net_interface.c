#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <sys/socket.h>

#include "net_interface.h"

void get_local_ip(char ip[INET_ADDRSTRLEN]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));

    remote.sin_family = AF_INET;
    remote.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);

    connect(sock, (struct sockaddr *)&remote, sizeof(remote));

    struct sockaddr_in local;
    socklen_t len = sizeof(local);

    getsockname(sock, (struct sockaddr *)&local, &len);
    inet_ntop(AF_INET, &local.sin_addr, ip, INET_ADDRSTRLEN);

    close(sock);
}

void get_mac_address(const char *ifname, char mac[18]) {
    struct ifaddrs *ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;

        struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;

        snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                 s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                 s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);

        freeifaddrs(ifaddr);
        return;
    }

    freeifaddrs(ifaddr);

    fprintf(stderr, "MAC da interface %s nao encontrado\n", ifname);
    exit(EXIT_FAILURE);
}

NetInterface get_net_interface(void) {
    char my_ip[INET_ADDRSTRLEN];
    get_local_ip(my_ip);

    struct ifaddrs *ifaddr;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    NetInterface netint = {0};

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

        char ip[INET_ADDRSTRLEN];
        char mask[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        inet_ntop(AF_INET, &netmask->sin_addr, mask, sizeof(mask));

        if (strcmp(ip, my_ip) != 0) continue;

        strcpy(netint.name, ifa->ifa_name);
        strcpy(netint.ip, ip);
        strcpy(netint.mask, mask);

        get_mac_address(netint.name, netint.mac);

        freeifaddrs(ifaddr);
        return netint;
    }

    freeifaddrs(ifaddr);

    fprintf(stderr, "Interface correspondente ao IP %s nao encontrada\n", my_ip);
    exit(EXIT_FAILURE);
}

void print_interface(NetInterface netint) {
    printf("Interface: %s\n", netint.name);
    printf("IP:        %s\n", netint.ip);
    printf("Mascara:   %s\n", netint.mask);
    printf("MAC:       %s\n", netint.mac);
}
