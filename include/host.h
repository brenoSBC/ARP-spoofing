#ifndef HOST_H
#define HOST_H

typedef struct {
    char ip[16];
    char mac[18];
} Host;

int host_exists(Host hosts[], int count, const char *ip);
void host_add(Host hosts[], int *count, int max_hosts, const char *ip, const char *mac);
void print_hosts(Host hosts[], int count);

#endif
