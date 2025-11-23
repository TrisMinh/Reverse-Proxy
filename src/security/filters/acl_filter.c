#include "../include/acl_filter.h"
#include "../include/ipset.h"
#include "dbhelper.h"
#include <stdio.h>
#include <string.h>
#include "../include/db_config.h"

static ipset_t g_blacklist;

void acl_init(void) {
    DBConfig *cf = get_db_config();
    if (db_connect(cf->host, cf->username, "", cf->database, cf->port) != 0) {
        printf("[ACL] Khong the ket noi DB!\n");
        return;
    }
    
    ipset_init(&g_blacklist);
    ipset_reload(&g_blacklist);
    printf("[ACL] ACL system initialized (DB + cache)\n");
}

void acl_reload(void) {
    int count = ipset_reload(&g_blacklist);
    printf("[ACL] Reloaded blacklist: %d IP(s)\n", count);
}

void acl_add(const char *ip, const char *domain) {
    if (!ip || strlen(ip) == 0) return;
    const char *d = (domain && domain[0]) ? domain : "*";
    ipset_save(&g_blacklist, ip, d);
    printf("[ACL] Added to blacklist: %s @ %s\n", ip, d);
}

void acl_remove(const char *ip, const char *domain) {
    if (!ip || strlen(ip) == 0) return;
    const char *d = (domain && domain[0]) ? domain : "*";
    ipset_delete(&g_blacklist, ip, d);
    printf("[ACL] Removed from blacklist: %s @ %s\n", ip, d);
}

FilterResult acl_filter(FilterContext *ctx) {
    if (!ctx || ctx->client_ip[0] == '\0')
        return FILTER_OK;

    // Lấy domain từ route context
    const char *domain = (ctx->route && ctx->route->domain[0] != '\0') ? ctx->route->domain : "*";
    
    // Kiểm tra blacklist (sẽ check cả global ban "*" và domain-specific ban)
    if (ipset_contains(&g_blacklist, ctx->client_ip, domain)) {
        printf("[ACL] Denied IP: %s @ domain: %s\n", ctx->client_ip, domain);
        return FILTER_DENY;
    }

    return FILTER_OK;
}

void acl_shutdown(void) {
    db_close();
    printf("[ACL] ACL system shutdown\n");
}
