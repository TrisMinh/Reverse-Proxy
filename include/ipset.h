#ifndef IPSET_H
#define IPSET_H

#include <windows.h>

#define MAX_IPS 1024

typedef struct {
    char ip[64];
    char domain[256];  // Domain hoặc "*" cho global ban
} ip_entry_t;

typedef struct {
    ip_entry_t list[MAX_IPS];
    int count;
} ipset_t;

void ipset_init(ipset_t *s);
int ipset_add(ipset_t *s, const char *ip, const char *domain);
int ipset_remove(ipset_t *s, const char *ip, const char *domain);
int ipset_contains(ipset_t *s, const char *ip, const char *domain);
int ipset_save(ipset_t *s, const char *ip, const char *domain);
int ipset_delete(ipset_t *s, const char *ip, const char *domain);
int ipset_reload(ipset_t *s);

#endif
