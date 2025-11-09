#include "ipset.h"
#include "dao_acl.h"
#include <stdio.h>

static CRITICAL_SECTION ipset_lock;
static int lock_init = 0;

static void ensure_lock() {
    if (!lock_init) {
        InitializeCriticalSection(&ipset_lock);
        lock_init = 1;
    }
}

void ipset_init(ipset_t *s) {
    s->count = 0;
}

int ipset_add(ipset_t *s, const char *ip) {
    if (s->count >= MAX_IPS) return -1;
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0)
            return 0;
    }
    strncpy(s->list[s->count].ip, ip, sizeof(s->list[s->count].ip) - 1);
    s->count++;
    return 1;
}

int ipset_remove(ipset_t *s, const char *ip) {
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0) {
            for (int j = i; j < s->count - 1; j++)
                s->list[j] = s->list[j + 1];
            s->count--;
            return 1;
        }
    }
    return 0;
}

int ipset_contains(ipset_t *s, const char *ip) {
    for (int i = 0; i < s->count; i++)
        if (strcmp(s->list[i].ip, ip) == 0)
            return 1;
    return 0;
}

int ipset_save(ipset_t *s, const char *ip) {
    if (!s || !ip) return -1;
    ensure_lock();
    EnterCriticalSection(&ipset_lock);

    if (dao_acl_exists(ip)) {
        printf("[ACL] %s da ton tai trong DB\n", ip);
        LeaveCriticalSection(&ipset_lock);
        return 0;
    }

    ipset_add(s, ip);
    if (dao_acl_add(ip) == 0)
        printf("[ACL] Da them '%s' vao DB blacklist\n", ip);
    else
        printf("[ACL] Loi khi them '%s'\n", ip);

    LeaveCriticalSection(&ipset_lock);
    return 1;
}

int ipset_delete(ipset_t *s, const char *ip) {
    if (!s || !ip) return -1;
    ensure_lock();
    EnterCriticalSection(&ipset_lock);

    ipset_remove(s, ip);
    dao_acl_remove(ip);

    printf("[ACL] Xoa '%s' khoi cache va DB\n", ip);

    LeaveCriticalSection(&ipset_lock);
    return 1;
}

int ipset_reload(ipset_t *s) {
    ensure_lock();
    EnterCriticalSection(&ipset_lock);
    int count = dao_acl_load_all(s);
    printf("[ACL] Reloaded %d IPs from DB\n", count);
    LeaveCriticalSection(&ipset_lock);
    return count;
}
