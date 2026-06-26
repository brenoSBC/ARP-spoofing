#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netpacket/packet.h>


/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    char name[64];
    char mask[16];
    char mac [18];
    char ip  [16];
} NetInterface;

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

        snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", s->sll_addr[0], s->sll_addr[1], s->sll_addr[2], s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);

        freeifaddrs(ifaddr);
        return;
    }

    freeifaddrs(ifaddr);

    fprintf(stderr, "MAC da interface %s não encontrado\n", ifname);
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

    fprintf(stderr, "Interface correspondente ao IP %s não encontrada\n", my_ip);
    exit(EXIT_FAILURE);
}

/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

int main(void) {

    NetInterface netint = get_net_interface();

    printf("Interface: %s\n", netint.name);
    printf("IP:        %s\n", netint.ip);
    printf("Mascara:   %s\n", netint.mask);
    printf("MAC:       %s\n", netint.mac);

    struct in_addr addr;
    struct in_addr mask;

    inet_pton(AF_INET, netint.ip, &addr);
    inet_pton(AF_INET, netint.mask, &mask);

    uint32_t n_mask = ntohl(mask.s_addr);
    int n_bits = sizeof(n_mask) * 8;

    int count = 0;
    for (int i = n_bits - 1; i >= 0; i--) {
        int bit = (n_mask >> i) & 1;
        if (bit) count++;
    }

    uint32_t n_decimal_mask = count;
    int exp = 32 - n_decimal_mask;
    int n_addrs = (1 << exp) - 2;

    printf("\n\nTAMANHO BITS N MASK: %d", n_bits);
    printf("\nMASCARA (/): %d", count);
    printf("\nEXP = %d", exp);
    printf("\nNUMERO DE HOSTS = %d\n\n", n_addrs);



    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask_num = ntohl(mask.s_addr);

    uint32_t network = ip & mask_num;
    uint32_t broadcast = network | (~mask_num);

    struct in_addr aux;
    char network_ip[INET_ADDRSTRLEN];
    char broadcast_ip[INET_ADDRSTRLEN];

    aux.s_addr = htonl(network);
    inet_ntop(AF_INET, &aux, network_ip, sizeof(network_ip));

    aux.s_addr = htonl(broadcast);
    inet_ntop(AF_INET, &aux, broadcast_ip, sizeof(broadcast_ip));

    printf("Network:   %s\n", network_ip);
    printf("Broadcast: %s\n\n", broadcast_ip);



    for (uint32_t target = network + 1; target < broadcast; target++) {

        if (target == ip) continue;

        struct in_addr target_addr;
        target_addr.s_addr = htonl(target);

        char target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &target_addr, target_ip, sizeof(target_ip));

        printf("Target IP: %s\n", target_ip);

        // send_arp_request(target_ip);
    }

    return 0;
}



// struct in_addr
// struct in_addr {
//     in_addr_t s_addr; // Inteiro de 32 bits sem sinal uint32_t
// };

//inet_pton
// "192.168.0.34" (texto) -> numero de 32 bits 
// inet_pton(AF_INET, netint.ip, &addr);
// espera a struct in_addr no ultimo argumento
// e coloca esse número em addr.s_addr

// inet_ntop (controtio do inet_pton)