#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include "net_interface.h"
#include "host.h"

#pragma pack(push, 1)

typedef struct {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    uint16_t eth_type;
} EthernetHeader;

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    unsigned char sender_mac[6];
    uint32_t sender_ip;
    unsigned char target_mac[6];
    uint32_t target_ip;
} ArpHeader;

typedef struct {
    EthernetHeader eth;
    ArpHeader arp;
} ArpPacket;

#pragma pack(pop)

void mac_str_to_bytes(const char *mac_str, unsigned char mac[6]);
void mac_bytes_to_str(const unsigned char mac[6], char mac_str[18]);

int arp_open_socket(void);
void get_network_range(NetInterface netint, uint32_t *network, uint32_t *broadcast);

ArpPacket arp_build_request(NetInterface netint, const char *target_ip_str);
ArpPacket arp_build_reply(
    const char *fake_sender_ip_str,
    const char *fake_sender_mac_str,
    const char *target_ip_str,
    const char *target_mac_str
);

void arp_send_packet(int sock, NetInterface netint, ArpPacket *packet);
int arp_scan(NetInterface netint, Host hosts[], int max_hosts);
void arp_spoof_once(NetInterface netint, Host victim, Host gateway);
void arp_restore(NetInterface netint, Host victim, Host gateway);

#endif
