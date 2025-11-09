#include "../include/proxy_routes.h"
#include "../include/logger.h"
#include "../include/dao_routes.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifndef MAX_PROXY_ROUTES
#define MAX_PROXY_ROUTES 4096
#endif

static ProxyRoute records[MAX_PROXY_ROUTES];
static int record_count = 0;
static CRITICAL_SECTION records_lock;
static int records_inited = 0;

static void ensure_init() {
    if (!records_inited) {
        InitializeCriticalSection(&records_lock);
        records_inited = 1;
    }
}

int load_proxy_routes() {
    ensure_init();

    ProxyRoute *tmp = (ProxyRoute*)malloc(sizeof(ProxyRoute) * MAX_PROXY_ROUTES);
    if (!tmp) {
        log_message("ERROR", "[routes] malloc failed");
        return 0;
    }

    int n = dao_routes_load_all_into(tmp, MAX_PROXY_ROUTES);
    if (n < 0) n = 0;
    if (n > MAX_PROXY_ROUTES) n = MAX_PROXY_ROUTES;

    EnterCriticalSection(&records_lock);
    memcpy(records, tmp, (size_t)n * sizeof(ProxyRoute));
    record_count = n;
    LeaveCriticalSection(&records_lock);

    free(tmp);

    char buf[96];
    snprintf(buf, sizeof(buf), "[routes] loaded %d row(s) from DAO", n);
    log_message("INFO", buf);
    return n;
}


const ProxyRoute* find_proxy_routes(const char *domain) {
    if (!domain) return NULL;
    ensure_init();

    EnterCriticalSection(&records_lock);
    for (int i = 0; i < record_count; ++i) {
        if (_stricmp(records[i].domain, domain) == 0) {
            const ProxyRoute *res = &records[i];
            LeaveCriticalSection(&records_lock);
            return res;
        }
    }
    LeaveCriticalSection(&records_lock);
    return NULL;
}
