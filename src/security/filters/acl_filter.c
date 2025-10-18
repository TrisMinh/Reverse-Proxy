#include "acl_filter.h"
#include <string.h>

static ipset_t g_blacklist;

void acl_init(const char *file) {
    ipset_init(&g_blacklist);
    if (file) ipset_load(&g_blacklist, file);
}

void acl_reload(const char *file) {
    if (file) ipset_load(&g_blacklist, file);
}

void acl_add(const char *ip) {
    ipset_add(&g_blacklist, ip);
    ipset_save(&g_blacklist, "../src/security/lists/blacklist.txt", ip);
    printf("[ACL] Added to blacklist: %s\n", ip);
}

void acl_remove(const char *ip) {
    ipset_remove(&g_blacklist, ip);
}

FilterResult acl_filter(FilterContext *ctx) {
    if (!ctx || ctx->client_ip[0] == '\0')
        return FILTER_OK;
    if (ipset_contains(&g_blacklist, ctx->client_ip))
        return FILTER_DENY;
    return FILTER_OK;
}