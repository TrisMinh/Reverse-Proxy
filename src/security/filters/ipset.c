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

int ipset_add(ipset_t *s, const char *ip, const char *domain) {
    if (s->count >= MAX_IPS) return -1;
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0)
            return 0;
    }
    strncpy(s->list[s->count].ip, ip, sizeof(s->list[s->count].ip) - 1);
    s->list[s->count].ip[sizeof(s->list[s->count].ip) - 1] = '\0';
    
    if (domain && domain[0] != '\0') {
        strncpy(s->list[s->count].domain, domain, sizeof(s->list[s->count].domain) - 1);
        s->list[s->count].domain[sizeof(s->list[s->count].domain) - 1] = '\0';
    } else {
        s->list[s->count].domain[0] = '\0';
    }
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

// Kiểm tra IP + Domain cụ thể
int ipset_contains_with_domain(ipset_t *s, const char *ip, const char *domain) {
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0) {
            // Nếu entry KHÔNG có domain → Chặn toàn bộ IP
            if (s->list[i].domain[0] == '\0') {
                return 1;  // Chặn tất cả domains
            }
            // Nếu entry CÓ domain → Chỉ chặn domain cụ thể
            if (domain && strcmp(s->list[i].domain, domain) == 0) {
                return 1;  // Chặn domain này
            }
        }
    }
    return 0;  // Không chặn
}

int ipset_save(ipset_t *s, const char *ip, const char *domain) {
    if (!s || !ip) return -1;
    ensure_lock();
    EnterCriticalSection(&ipset_lock);

    if (dao_acl_exists(ip)) {
        printf("[ACL] %s da ton tai trong DB\n", ip);
        LeaveCriticalSection(&ipset_lock);
        return 0;
    }

    ipset_add(s, ip, domain);
    if (dao_acl_add(ip, domain) == 0) {
        if (domain && domain[0] != '\0') {
            printf("[ACL] Da them '%s' (domain: %s) vao DB blacklist\n", ip, domain);
        } else {
            printf("[ACL] Da them '%s' vao DB blacklist\n", ip);
        }
    } else {
        printf("[ACL] Loi khi them '%s'\n", ip);
    }

    LeaveCriticalSection(&ipset_lock);
    return 1;
}

int ipset_delete(ipset_t *s, const char *ip) {
    if (!s || !ip) return -1;
    ensure_lock();
    EnterCriticalSection(&ipset_lock);

    // Tìm domain trước khi xóa
    char domain[256] = {0};
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0) {
            strncpy(domain, s->list[i].domain, sizeof(domain) - 1);
            break;
        }
    }

    ipset_remove(s, ip);
    dao_acl_remove(ip);

    if (domain[0] != '\0') {
        printf("[ACL] Xoa '%s' (domain: %s) khoi cache va DB\n", ip, domain);
    } else {
        printf("[ACL] Xoa '%s' khoi cache va DB\n", ip);
    }

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
