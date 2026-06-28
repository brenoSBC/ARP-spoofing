#include <stdio.h>
#include <string.h>

#include "host.h"

int host_exists(Host hosts[], int count, const char *ip) {
    for (int i = 0; i < count; i++) {
        if (strcmp(hosts[i].ip, ip) == 0) {
            return 1;
        }
    }

    return 0;
}

void host_add(Host hosts[], int *count, int max_hosts, const char *ip, const char *mac) {
    if (*count >= max_hosts) return;
    if (host_exists(hosts, *count, ip)) return;

    strcpy(hosts[*count].ip, ip);
    strcpy(hosts[*count].mac, mac);

    (*count)++;
}

void print_hosts(Host hosts[], int count) {
    printf("\nHosts encontrados:\n\n");

    if (count == 0) {
        printf("Nenhum host encontrado.\n");
        return;
    }

    for (int i = 0; i < count; i++) {
        printf("[%d] IP: %-15s MAC: %s\n", i, hosts[i].ip, hosts[i].mac);
    }
}
