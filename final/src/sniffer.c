#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "sniffer.h"

#define MAX_PRINTED_SNI 512
#define MAX_SNI_LEN 255

#pragma pack(push, 1)
typedef struct {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    uint16_t eth_type;
} EthernetHeader;
#pragma pack(pop)

static char printed_sni[MAX_PRINTED_SNI][MAX_SNI_LEN + 1];
static int printed_sni_count = 0;

static void ip_to_str(uint32_t ip_addr, char out[INET_ADDRSTRLEN]) {
    struct in_addr addr;
    addr.s_addr = ip_addr;
    inet_ntop(AF_INET, &addr, out, INET_ADDRSTRLEN);
}

static uint16_t read_u16_be(const unsigned char *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read_u24_be(const unsigned char *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}


static void reverse_dns_lookup(const char *ip_str, char host_out[NI_MAXHOST]) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_str, &addr.sin_addr) != 1) {
        strcpy(host_out, "-");
        return;
    }

    int result = getnameinfo(
        (struct sockaddr *)&addr,
        sizeof(addr),
        host_out,
        NI_MAXHOST,
        NULL,
        0,
        0
    );

    if (result != 0) {
        strcpy(host_out, "-");
    }
}

static int is_victim_packet(const char *src_ip, const char *dst_ip, const char *victim_ip) {
    return strcmp(src_ip, victim_ip) == 0 || strcmp(dst_ip, victim_ip) == 0;
}

static int bind_to_interface(int sock, const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        perror("if_nametoindex sniffer");
        return -1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));

    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = (int)ifindex;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind sniffer");
        return -1;
    }

    return 0;
}

static int sni_already_printed(const char *sni) {
    for (int i = 0; i < printed_sni_count; i++) {
        if (strcmp(printed_sni[i], sni) == 0) {
            return 1;
        }
    }
    return 0;
}

static void mark_sni_printed(const char *sni) {
    if (printed_sni_count >= MAX_PRINTED_SNI) {
        return;
    }

    strncpy(printed_sni[printed_sni_count], sni, MAX_SNI_LEN);
    printed_sni[printed_sni_count][MAX_SNI_LEN] = '\0';
    printed_sni_count++;
}

/*
    Tenta extrair SNI de um TLS ClientHello.

    Estrutura simplificada que estamos lendo:

    TLS Record:
      1 byte  content_type        deve ser 0x16 (Handshake)
      2 bytes version             normalmente 0x0301, 0x0303...
      2 bytes record_length

    Handshake:
      1 byte  handshake_type      deve ser 0x01 (ClientHello)
      3 bytes handshake_length

    ClientHello:
      2 bytes version
      32 bytes random
      1 byte session_id_length
      N bytes session_id
      2 bytes cipher_suites_length
      N bytes cipher_suites
      1 byte compression_methods_length
      N bytes compression_methods
      2 bytes extensions_length
      extensoes...

    Extensao SNI:
      type = 0x0000
*/
static int extract_sni_from_tls_client_hello(
    const unsigned char *payload,
    int payload_len,
    char sni_out[MAX_SNI_LEN + 1]
) {
    if (payload_len < 5) {
        return 0;
    }

    int pos = 0;

    /* TLS Handshake record */
    if (payload[pos] != 0x16) {
        return 0;
    }

    /* Versao TLS tem major 0x03 para SSLv3/TLS 1.x */
    if (payload[pos + 1] != 0x03) {
        return 0;
    }

    int record_len = read_u16_be(payload + pos + 3);
    pos += 5;

    if (record_len <= 0 || payload_len < pos + record_len) {
        /* Pode estar fragmentado em mais de um segmento TCP. Por enquanto ignoramos. */
        return 0;
    }

    if (payload_len < pos + 4) {
        return 0;
    }

    /* Handshake type: ClientHello */
    if (payload[pos] != 0x01) {
        return 0;
    }

    int handshake_len = (int)read_u24_be(payload + pos + 1);
    pos += 4;

    if (handshake_len <= 0 || payload_len < pos + handshake_len) {
        return 0;
    }

    int hello_end = pos + handshake_len;

    /* client_version + random */
    if (pos + 2 + 32 > hello_end) {
        return 0;
    }
    pos += 2 + 32;

    /* session_id */
    if (pos + 1 > hello_end) {
        return 0;
    }
    int session_id_len = payload[pos];
    pos += 1;

    if (pos + session_id_len > hello_end) {
        return 0;
    }
    pos += session_id_len;

    /* cipher_suites */
    if (pos + 2 > hello_end) {
        return 0;
    }
    int cipher_suites_len = read_u16_be(payload + pos);
    pos += 2;

    if (pos + cipher_suites_len > hello_end) {
        return 0;
    }
    pos += cipher_suites_len;

    /* compression_methods */
    if (pos + 1 > hello_end) {
        return 0;
    }
    int compression_methods_len = payload[pos];
    pos += 1;

    if (pos + compression_methods_len > hello_end) {
        return 0;
    }
    pos += compression_methods_len;

    /* extensions */
    if (pos + 2 > hello_end) {
        return 0;
    }
    int extensions_len = read_u16_be(payload + pos);
    pos += 2;

    if (pos + extensions_len > hello_end) {
        return 0;
    }

    int extensions_end = pos + extensions_len;

    while (pos + 4 <= extensions_end) {
        uint16_t ext_type = read_u16_be(payload + pos);
        uint16_t ext_len = read_u16_be(payload + pos + 2);
        pos += 4;

        if (pos + ext_len > extensions_end) {
            return 0;
        }

        if (ext_type == 0x0000) {
            /* server_name extension */
            int sni_pos = pos;
            int sni_end = pos + ext_len;

            if (sni_pos + 2 > sni_end) {
                return 0;
            }

            int server_name_list_len = read_u16_be(payload + sni_pos);
            sni_pos += 2;

            if (sni_pos + server_name_list_len > sni_end) {
                return 0;
            }

            while (sni_pos + 3 <= sni_end) {
                uint8_t name_type = payload[sni_pos];
                uint16_t name_len = read_u16_be(payload + sni_pos + 1);
                sni_pos += 3;

                if (sni_pos + name_len > sni_end) {
                    return 0;
                }

                /* name_type 0 = host_name */
                if (name_type == 0) {
                    if (name_len > MAX_SNI_LEN) {
                        name_len = MAX_SNI_LEN;
                    }

                    memcpy(sni_out, payload + sni_pos, name_len);
                    sni_out[name_len] = '\0';
                    return 1;
                }

                sni_pos += name_len;
            }
        }

        pos += ext_len;
    }

    return 0;
}

static void process_tcp_packet(
    const unsigned char *buffer,
    ssize_t bytes,
    int ip_header_len,
    const char *src_ip,
    const char *dst_ip,
    SnifferStats *stats
) {
    const unsigned char *transport = buffer + sizeof(EthernetHeader) + ip_header_len;
    ssize_t transport_available = bytes - (ssize_t)sizeof(EthernetHeader) - ip_header_len;

    if (transport_available < (ssize_t)sizeof(struct tcphdr)) {
        return;
    }

    const struct tcphdr *tcp = (const struct tcphdr *)transport;
    int tcp_header_len = tcp->doff * 4;

    if (tcp_header_len < 20 || transport_available < tcp_header_len) {
        return;
    }

    int src_port = ntohs(tcp->source);
    int dst_port = ntohs(tcp->dest);

    const unsigned char *payload = transport + tcp_header_len;
    int payload_len = (int)transport_available - tcp_header_len;

    if (stats != NULL) {
        stats->tcp_packets++;
        if (src_port == 443 || dst_port == 443) {
            stats->https_bytes += (unsigned long)bytes;
        }
    }

    if (payload_len <= 0) {
        return;
    }

    /* Só tentamos SNI quando parece HTTPS/TLS em TCP 443. */
    if (src_port != 443 && dst_port != 443) {
        return;
    }

    char sni[MAX_SNI_LEN + 1];
    sni[0] = '\0';

    int found_sni = extract_sni_from_tls_client_hello(payload, payload_len, sni);

    if (payload_len >= 6 && payload[0] == 0x16 && payload[5] == 0x01) {
        if (stats != NULL) {
            stats->tls_client_hello++;
        }
    }

    if (found_sni) {
        if (stats != NULL) {
            stats->sni_found++;
        }

        if (!sni_already_printed(sni)) {
            char reverse_dns[NI_MAXHOST];
            reverse_dns_lookup(dst_ip, reverse_dns);

            mark_sni_printed(sni);
            printf("[SNI] vitima=%s -> destino=%s:%d | dominio=%s | dns_reverso=%s | bytes=%zd\n",
                   src_ip, dst_ip, dst_port, sni, reverse_dns, bytes);
            fflush(stdout);
        }
    }
}

static void process_udp_packet(
    const unsigned char *buffer,
    ssize_t bytes,
    int ip_header_len,
    SnifferStats *stats
) {
    const unsigned char *transport = buffer + sizeof(EthernetHeader) + ip_header_len;
    ssize_t transport_available = bytes - (ssize_t)sizeof(EthernetHeader) - ip_header_len;

    if (transport_available < (ssize_t)sizeof(struct udphdr)) {
        return;
    }

    const struct udphdr *udp = (const struct udphdr *)transport;
    int src_port = ntohs(udp->source);
    int dst_port = ntohs(udp->dest);

    if (stats != NULL) {
        stats->udp_packets++;
        if (src_port == 443 || dst_port == 443) {
            stats->https_bytes += (unsigned long)bytes;
        }
    }

    /*
        UDP/443 geralmente e QUIC/HTTP3.
        Este codigo ainda nao extrai SNI de QUIC. Para evitar spam, nao imprimimos cada pacote UDP.
    */
}

void sniff_packets(NetInterface netint, Host victim, volatile sig_atomic_t *running, SnifferStats *stats) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0) {
        perror("socket sniffer");
        exit(EXIT_FAILURE);
    }

    if (bind_to_interface(sock, netint.name) < 0) {
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("\nSniffer iniciado na interface %s\n", netint.name);
    printf("Filtrando pacotes que envolvem a vitima %s\n", victim.ip);
    printf("Saida limpa: mostrando apenas dominios SNI encontrados em TLS ClientHello.\n\n");
    fflush(stdout);

    unsigned char buffer[65536];

    while (*running) {
        ssize_t bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);

        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }

            perror("recvfrom sniffer");
            break;
        }

        if (bytes < (ssize_t)sizeof(EthernetHeader)) {
            continue;
        }

        if (stats != NULL) {
            stats->total_packets++;
        }

        EthernetHeader *eth = (EthernetHeader *)buffer;
        uint16_t eth_type = ntohs(eth->eth_type);

        if (eth_type != ETH_P_IP) {
            continue;
        }

        if (bytes < (ssize_t)(sizeof(EthernetHeader) + sizeof(struct iphdr))) {
            continue;
        }

        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(EthernetHeader));
        int ip_header_len = ip->ihl * 4;

        if (ip_header_len < 20) {
            continue;
        }

        if (bytes < (ssize_t)(sizeof(EthernetHeader) + ip_header_len)) {
            continue;
        }

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        ip_to_str(ip->saddr, src_ip);
        ip_to_str(ip->daddr, dst_ip);

        if (!is_victim_packet(src_ip, dst_ip, victim.ip)) {
            continue;
        }

        if (stats != NULL) {
            stats->victim_packets++;
            stats->total_bytes += (unsigned long)bytes;
        }

        if (ip->protocol == IPPROTO_TCP) {
            process_tcp_packet(buffer, bytes, ip_header_len, src_ip, dst_ip, stats);
        }
        else if (ip->protocol == IPPROTO_UDP) {
            process_udp_packet(buffer, bytes, ip_header_len, stats);
        }
        else if (ip->protocol == IPPROTO_ICMP) {
            if (stats != NULL) {
                stats->icmp_packets++;
            }
        }
    }

    close(sock);
}


