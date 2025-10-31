#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <windows.h>
#include "../include/ipset.h"

static MYSQL *g_conn = NULL;
static CRITICAL_SECTION ipset_lock;
static int ipset_lock_initialized = 0;

void ipset_global_lock_init() {
    if (!ipset_lock_initialized) {
        InitializeCriticalSection(&ipset_lock);
        ipset_lock_initialized = 1;
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
    s->list[s->count].ip[sizeof(s->list[s->count].ip) - 1] = '\0';
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
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0)
            return 1;
    }
    return 0;
}

// MYSQL
int ipdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port) {
    g_conn = mysql_init(NULL);
    if (!g_conn) {
        printf("[MYSQL] init failed\n");
        return -1;
    }

    if (!mysql_real_connect(g_conn, host, user, pass, db, port, NULL, 0)) {
        printf("[MYSQL] connect failed: %s\n", mysql_error(g_conn));
        return -1;
    }

    printf("[MYSQL] Connected to %s:%u\n", host, port);
    return 0;
}

void ipdb_close() {
    if (g_conn) {
        mysql_close(g_conn);
        g_conn = NULL;
    }
}

// DB Helper

int ipdb_add(const char *ip) {
    if (!g_conn || !ip) return -1;

    char query[256];
    snprintf(query, sizeof(query),
             "INSERT IGNORE INTO blacklist (ip, created_at) VALUES ('%s', NOW())", ip);

    if (mysql_query(g_conn, query) == 0)
        return 0;

    printf("[MYSQL] add error: %s\n", mysql_error(g_conn));
    return -1;
}

int ipdb_exists(const char *ip) {
    if (!g_conn || !ip) return 0;

    char query[256];
    snprintf(query, sizeof(query),
             "SELECT 1 FROM blacklist WHERE ip='%s' LIMIT 1", ip);

    if (mysql_query(g_conn, query)) {
        printf("[MYSQL] exists query error: %s\n", mysql_error(g_conn));
        return 0;
    }

    MYSQL_RES *res = mysql_store_result(g_conn);
    if (!res) return 0;

    int exists = mysql_num_rows(res) > 0;
    mysql_free_result(res);
    return exists;
}

int ipdb_remove(const char *ip) {
    if (!g_conn || !ip) return -1;

    char query[256];
    snprintf(query, sizeof(query),
             "DELETE FROM blacklist WHERE ip='%s'", ip);

    if (mysql_query(g_conn, query) == 0)
        return 0;

    printf("[MYSQL] delete error: %s\n", mysql_error(g_conn));
    return -1;
}

int ipdb_load_all(ipset_t *s) {
    if (!g_conn || !s) return -1;

    if (mysql_query(g_conn, "SELECT ip FROM blacklist")) {
        printf("[MYSQL] load all error: %s\n", mysql_error(g_conn));
        return -1;
    }

    MYSQL_RES *res = mysql_store_result(g_conn);
    if (!res) return -1;

    MYSQL_ROW row;
    int count = 0;
    ipset_init(s);

    while ((row = mysql_fetch_row(res))) {
        if (row[0]) {
            ipset_add(s, row[0]);
            count++;
        }
    }
    mysql_free_result(res);
    printf("[MYSQL] loaded %d IPs into cache\n", count);
    return count;
}

int ipset_save(ipset_t *s, const char *unused, const char *ip) {
    if (!s || !ip) {
        printf("[ACL] ipset_save: tham so NULL\n");
        return -1;
    }

    ipset_global_lock_init();
    EnterCriticalSection(&ipset_lock);

    if (ipdb_exists(ip)) {
        printf("[ACL] %s da co trong blacklist (DB), bo qua\n", ip);
        LeaveCriticalSection(&ipset_lock);
        return 0;
    }

    ipset_add(s, ip);
    printf("[ACL] Dang them %s vao blacklist...\n", ip);

    if (ipdb_add(ip) == 0)
        printf("[ACL] Da them '%s' vao DB blacklist\n", ip);
    else
        printf("[ACL] Loi khi them '%s' vao DB\n", ip);

    LeaveCriticalSection(&ipset_lock);
    return 1;
}

int ipset_delete(ipset_t *s, const char *ip) {
    if (!s || !ip) {
        printf("[ACL] ipset_delete: tham so NULL\n");
        return -1;
    }

    ipset_global_lock_init();
    EnterCriticalSection(&ipset_lock);

    if (ipset_remove(s, ip))
        printf("[ACL] Da xoa '%s' khoi cache\n", ip);
    else
        printf("[ACL] '%s' khong ton tai trong cache\n", ip);

    if (ipdb_remove(ip) == 0)
        printf("[ACL] Da xoa '%s' khoi DB\n", ip);
    else
        printf("[ACL] Loi khi xoa '%s' khoi DB\n", ip);

    LeaveCriticalSection(&ipset_lock);
    return 1;
}


int ipset_reload(ipset_t *s) {
    if (!s) return -1;

    ipset_global_lock_init();
    EnterCriticalSection(&ipset_lock);
    int count = ipdb_load_all(s);
    // printf("[ACL] Reload DB to cache: %d IP(s)\n", count);
    LeaveCriticalSection(&ipset_lock);

    return count;
}
