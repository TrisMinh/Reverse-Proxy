#include "../include/proxy_routes.h"
#include "../include/logger.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <ctype.h>

#ifndef MAX_PROXY_ROUTES
#define MAX_PROXY_ROUTES 4096
#endif

static ProxyRoute records[MAX_PROXY_ROUTES];
static int record_count = 0;
static CRITICAL_SECTION records_lock;
static int records_inited = 0;

static void ensure_init(void) {
    if (!records_inited) {
        InitializeCriticalSection(&records_lock);
        records_inited = 1;
    }
}

static void trim(char *s) {
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    int len = (int)strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) {
        s[len-1] = '\0';
        len--;
    }
}

static int parse_host_port_ipv4(const char *in, char *host_out, size_t host_sz, int *port_out)
{
    if (!in || !*in || !host_out || host_sz == 0 || !port_out) return -1;

    *port_out = 0;

    const char *colon = strrchr(in, ':');
    if (colon && colon > in) {
        size_t host_len = (size_t)(colon - in);
        if (host_len >= host_sz) host_len = host_sz - 1;
        memcpy(host_out, in, host_len);
        host_out[host_len] = '\0';

        *port_out = atoi(colon + 1);
    } else {
        strncpy(host_out, in, host_sz - 1);
        host_out[host_sz - 1] = '\0';
    }
    return 0;
}

int load_proxy_routes(const char *filename) {
    ensure_init();
    EnterCriticalSection(&records_lock);

    FILE *f = fopen(filename, "r");
    if (!f) {
        record_count = 0;
        LeaveCriticalSection(&records_lock);
        char buf[256]; 
        snprintf(buf, sizeof(buf), "Proxy routes file not found: %s", filename);
        log_message("WARN", buf);
        return 0;
    }

    char line[512];
    int loaded = 0;
    record_count = 0;

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char domain[256], backend[256];
        if (sscanf(line, "%255s %255s", domain, backend) != 2) continue;

        trim(domain); 
        trim(backend);

        if (record_count < MAX_PROXY_ROUTES) {
            char host_only[256];
            int port = 0;
            if (parse_host_port_ipv4(backend, host_only, sizeof(host_only), &port) != 0) {
                continue;
            }

            strncpy(records[record_count].domain, domain, sizeof(records[record_count].domain)-1);
            records[record_count].domain[sizeof(records[record_count].domain)-1] = '\0';

            strncpy(records[record_count].backend_host, host_only, sizeof(records[record_count].backend_host)-1);
            records[record_count].backend_host[sizeof(records[record_count].backend_host)-1] = '\0';
            records[record_count].backend_port = port; 
            records[record_count].is_https = -1;

            record_count++;
            loaded++;
        } else {
            log_message("ERROR", "Proxy routes capacity reached; skipping remaining");
            break;
        }
    }

    fclose(f);
    char buf[128];
    snprintf(buf, sizeof(buf), "Loaded %d proxy routes from %s", loaded, filename);
    log_message("INFO", buf);
    LeaveCriticalSection(&records_lock);
    return loaded;
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
