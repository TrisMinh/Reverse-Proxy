#include "../include/request_metrics.h"
#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#define REQUEST_TRACKER_HASH_SIZE 256

typedef struct request_counter_node_s {
    request_counter_t counter;
    struct request_counter_node_s *next; 
} request_counter_node_t;

typedef struct request_tracker_state_s {
    request_counter_node_t *hash_table[REQUEST_TRACKER_HASH_SIZE];
    request_minute_stats_t minute_stats;
    SRWLOCK lock;
    int initialized;
} request_tracker_state_t;

static request_tracker_state_t g_tracker;


static uint32_t hash_route_method_status_host(const char *route, const char *method, uint32_t status_code, const char *host) {
    uint32_t hash = 0;

    for (const char *p = route; *p; p++) {
        hash = hash * 31 + (unsigned char)*p;
    }

    for (const char *p = method; *p; p++) {
        hash = hash * 31 + (unsigned char)*p;
    }

    hash = hash * 31 + status_code;

    if (host) {
        for (const char *p = host; *p; p++) {
            hash = hash * 31 + (unsigned char)*p;
        }
    }
    
    return hash % REQUEST_TRACKER_HASH_SIZE;
}

static request_counter_node_t* find_or_create_counter(
    const char *route, 
    const char *method, 
    uint32_t status_code,
    const char *host
) {
    uint32_t hash = hash_route_method_status_host(route, method, status_code, host);
    request_counter_node_t *node = g_tracker.hash_table[hash];

    while (node) {
        if (strcmp(node->counter.route, route) == 0 &&
            strcmp(node->counter.method, method) == 0 &&
            node->counter.status_code == status_code &&
            strcmp(node->counter.host, host ? host : "") == 0) {
            return node;
        }
        node = node->next;
    }

    node = (request_counter_node_t*)calloc(1, sizeof(request_counter_node_t));
    if (!node) {
        return NULL;
    }
    
    strncpy(node->counter.route, route, sizeof(node->counter.route) - 1);
    strncpy(node->counter.method, method, sizeof(node->counter.method) - 1);
    node->counter.status_code = status_code;
    strncpy(node->counter.status_category, get_status_category(status_code), 
            sizeof(node->counter.status_category) - 1);
    node->counter.status_category[3] = '\0';
    if (host) {
        strncpy(node->counter.host, host, sizeof(node->counter.host) - 1);
        node->counter.host[sizeof(node->counter.host) - 1] = '\0';
    } else {
        node->counter.host[0] = '\0';
    }

    node->next = g_tracker.hash_table[hash];
    g_tracker.hash_table[hash] = node;
    
    return node;
}

static time_t get_current_minute(void) {
    time_t now = time(NULL);
    return now - (now % 60);
}

int request_tracker_init(void) {
    if (g_tracker.initialized) {
        return 0;
    }
    
    memset(&g_tracker, 0, sizeof(g_tracker));
    InitializeSRWLock(&g_tracker.lock);
    
    time_t now = get_current_minute();
    g_tracker.minute_stats.timestamp = now;
    
    g_tracker.initialized = 1;
    
    log_message("INFO", "Request tracker initialized");
    return 0;
}

void request_tracker_shutdown(void) {
    if (!g_tracker.initialized) {
        return;
    }
    
    AcquireSRWLockExclusive(&g_tracker.lock);

    for (int i = 0; i < REQUEST_TRACKER_HASH_SIZE; i++) {
        request_counter_node_t *node = g_tracker.hash_table[i];
        while (node) {
            request_counter_node_t *next = node->next;
            free(node);
            node = next;
        }
        g_tracker.hash_table[i] = NULL;
    }
    
    ReleaseSRWLockExclusive(&g_tracker.lock);
    
    g_tracker.initialized = 0;
    log_message("INFO", "Request tracker shutdown");
}

int request_tracker_record(
    const char *route,
    const char *method,
    uint32_t status_code,
    const char *host,
    uint64_t bytes_in,
    uint64_t bytes_out,
    int was_cache_hit
) {
    if (!g_tracker.initialized || !route || !method) {
        return -1;
    }

    if (strlen(route) >= 512 || strlen(method) >= 10) {
        return -1;
    }
    if (host && strlen(host) >= 256) {
        return -1;
    }

    static int call_count = 0;
    if (call_count < 5) {
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "[TRACKER] Recording: route=%s, method=%s, status=%u, host=%s, bytes_in=%llu, bytes_out=%llu, cache_hit=%d", 
                 route, method, status_code, host ? host : "(null)", (unsigned long long)bytes_in, (unsigned long long)bytes_out, was_cache_hit);
        log_message("INFO", log_buf);
        call_count++;
    }
    
    AcquireSRWLockExclusive(&g_tracker.lock);

    time_t current_minute = get_current_minute();
    if (current_minute != g_tracker.minute_stats.timestamp) {
        g_tracker.minute_stats.total_requests = 0;
        g_tracker.minute_stats.requests_2xx = 0;
        g_tracker.minute_stats.requests_4xx = 0;
        g_tracker.minute_stats.requests_5xx = 0;
        g_tracker.minute_stats.total_bytes_in = 0;
        g_tracker.minute_stats.total_bytes_out = 0;
        g_tracker.minute_stats.total_cache_hits = 0;
        g_tracker.minute_stats.total_cache_misses = 0;
        g_tracker.minute_stats.peak_requests_min = 0;
        g_tracker.minute_stats.timestamp = current_minute;
    }

    request_counter_node_t *node = find_or_create_counter(route, method, status_code, host);
    if (!node) {
        ReleaseSRWLockExclusive(&g_tracker.lock);
        return -1;
    }

    node->counter.request_count++;
    node->counter.bytes_in += bytes_in;
    node->counter.bytes_out += bytes_out;
    if (was_cache_hit) {
        node->counter.cache_hits++;
    } else {
        node->counter.cache_misses++;
    }

    g_tracker.minute_stats.total_requests++;
    g_tracker.minute_stats.total_bytes_in += bytes_in;
    g_tracker.minute_stats.total_bytes_out += bytes_out;
    if (was_cache_hit) {
        g_tracker.minute_stats.total_cache_hits++;
    } else {
        g_tracker.minute_stats.total_cache_misses++;
    }

    if (status_code >= 200 && status_code < 300) {
        g_tracker.minute_stats.requests_2xx++;
    } else if (status_code >= 400 && status_code < 500) {
        g_tracker.minute_stats.requests_4xx++;
    } else if (status_code >= 500) {
        g_tracker.minute_stats.requests_5xx++;
    }

    if (g_tracker.minute_stats.total_requests > g_tracker.minute_stats.peak_requests_min) {
        g_tracker.minute_stats.peak_requests_min = g_tracker.minute_stats.total_requests;
    }
    
    ReleaseSRWLockExclusive(&g_tracker.lock);
    
    return 0;
}

request_minute_stats_t* request_tracker_get_current_minute(void) {
    if (!g_tracker.initialized) {
        return NULL;
    }

    return &g_tracker.minute_stats;
}

request_counter_t* request_tracker_get_snapshot(void) {
    if (!g_tracker.initialized) {
        return NULL;
    }
    
    AcquireSRWLockShared(&g_tracker.lock);

    int count = 0;
    for (int i = 0; i < REQUEST_TRACKER_HASH_SIZE; i++) {
        request_counter_node_t *node = g_tracker.hash_table[i];
        while (node) {
            count++;
            node = node->next;
        }
    }
    
    if (count == 0) {
        ReleaseSRWLockShared(&g_tracker.lock);
        return NULL;
    }

    request_counter_t *head = NULL;
    request_counter_t *tail = NULL;
    
    for (int i = 0; i < REQUEST_TRACKER_HASH_SIZE; i++) {
        request_counter_node_t *node = g_tracker.hash_table[i];
        while (node) {
            request_counter_t *copy = (request_counter_t*)malloc(sizeof(request_counter_t));
            if (!copy) {
                while (head) {
                    request_counter_t *next = head->next;
                    free(head);
                    head = next;
                }
                ReleaseSRWLockShared(&g_tracker.lock);
                return NULL;
            }
            
            memcpy(copy, &node->counter, sizeof(request_counter_t));
            copy->next = NULL;
            
            if (!head) {
                head = tail = copy;
            } else {
                tail->next = copy;
                tail = copy;
            }
            
            node = node->next;
        }
    }
    
    ReleaseSRWLockShared(&g_tracker.lock);
    
    return head;
}

void request_tracker_reset(void) {
    if (!g_tracker.initialized) {
        return;
    }
    
    AcquireSRWLockExclusive(&g_tracker.lock);

    for (int i = 0; i < REQUEST_TRACKER_HASH_SIZE; i++) {
        request_counter_node_t *node = g_tracker.hash_table[i];
        while (node) {
            request_counter_node_t *next = node->next;
            free(node);
            node = next;
        }
        g_tracker.hash_table[i] = NULL;
    }

    memset(&g_tracker.minute_stats, 0, sizeof(g_tracker.minute_stats));
    g_tracker.minute_stats.timestamp = get_current_minute();
    
    ReleaseSRWLockExclusive(&g_tracker.lock);
}

