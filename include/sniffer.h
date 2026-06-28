#ifndef SNIFFER_H
#define SNIFFER_H

#include <signal.h>
#include <stdint.h>

#include "net_interface.h"
#include "host.h"

typedef struct {
    unsigned long total_packets;
    unsigned long victim_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long total_bytes;

    unsigned long tls_client_hello;
    unsigned long sni_found;
    unsigned long https_bytes;
} SnifferStats;

void sniff_packets(NetInterface netint, Host victim, volatile sig_atomic_t *running, SnifferStats *stats);

#endif
