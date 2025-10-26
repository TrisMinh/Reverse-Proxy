
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/rate_limit.h"
#include "../include/acl_filter.h"

/*
   Simple per-IP token bucket rate limiter
   Defaults: rate = 10 req/s, burst = 20 tokens
   Thread-safe with a single CRITICAL_SECTION protecting the map.

   Map: fixed-size hash table with chaining. Opportunistic eviction of idle entries (> 10 minutes).
*/

#define RL_DEFAULT_RATE   2.0  /* tokens per second */
#define RL_DEFAULT_BURST  20.0  /* max tokens */
#define RL_IDLE_EVICT_MS  (10ULL * 60ULL * 1000ULL)
#define RL_BUCKETS        1024

static rl_entry_t *g_buckets[RL_BUCKETS];
static CRITICAL_SECTION g_rl_lock;
static int g_rl_initialized = 0;
static double g_rate = RL_DEFAULT_RATE;
static double g_burst = RL_DEFAULT_BURST;

static uint64_t now_ms(void) {
    return GetTickCount64();
}

// đọc thêm phần này hiểu rõ hash
static unsigned hash_ip(const char *ip) {
    unsigned h = 2166136261u;
    while (*ip) {
        h ^= (unsigned char)(*ip++);
        h *= 16777619u;
    }
    // Sài phép % thì tốn CPU còn sài & thì lệnh máy nên rất nhanh
    return h & (RL_BUCKETS - 1);
}

void rate_limit_init(void)
{
    if (!g_rl_initialized) {
        InitializeCriticalSection(&g_rl_lock);
        for (int i = 0; i < RL_BUCKETS; ++i) g_buckets[i] = NULL;
        g_rl_initialized = 1;
    }
}

void rate_limit_shutdown(void)
{
    if (!g_rl_initialized) return;
    EnterCriticalSection(&g_rl_lock);
    for (int i = 0; i < RL_BUCKETS; ++i) {
        rl_entry_t *e = g_buckets[i];
        while (e) {
            rl_entry_t *n = e->next;
            free(e);
            e = n;
        }
        g_buckets[i] = NULL;
    }
    LeaveCriticalSection(&g_rl_lock);
    DeleteCriticalSection(&g_rl_lock);
    g_rl_initialized = 0;
}

static rl_entry_t *get_or_create(const char *ip, uint64_t now)
{
    unsigned idx = hash_ip(ip);
    rl_entry_t *prev = NULL, *e = g_buckets[idx];

    while (e) {
        if (strncmp(e->ip, ip, sizeof(e->ip)) == 0) {
            return e;
        }
        // Xóa entry quá hạn
        if (now - e->last_ms > RL_IDLE_EVICT_MS) {
            rl_entry_t *victim = e;
            rl_entry_t *next = e->next;
            if (prev) prev->next = next; else g_buckets[idx] = next;
            free(victim);
            e = next;
            continue;
        }
        prev = e;
        e = e->next;
    }

    // chọn LIFO vì nó nhanh gọn tiện
    rl_entry_t *ne = (rl_entry_t*)calloc(1, sizeof(rl_entry_t));
    if (!ne) return NULL;
    strncpy(ne->ip, ip, sizeof(ne->ip) - 1);
    ne->burst = g_burst;
    ne->tokens = g_burst; /* start full */
    ne->last_ms = now;
    ne->next = g_buckets[idx];
    g_buckets[idx] = ne;
    return ne;
}

static void refill(rl_entry_t *e, uint64_t now)
{
    if (!e) return;
    uint64_t elapsed_ms = now - e->last_ms;
    if (elapsed_ms == 0) return;
    double add = g_rate * ((double)elapsed_ms / 1000.0);
    e->tokens += add;
    if (e->tokens > e->burst) e->tokens = e->burst;
    e->last_ms = now;
}

FilterResult rate_limit_filter(FilterContext *ctx)
{
    if (!ctx) return FILTER_OK; /* fail-open */
    if (!g_rl_initialized) rate_limit_init();
    if (ctx->client_ip[0] == '\0') return FILTER_OK;

    uint64_t t = now_ms();
    EnterCriticalSection(&g_rl_lock);
    // phần này nếu k cấp phát được thì xảy ra lỗ hổng lớn làm cho hệ thống k quản lý được token => ip này ddos thì chết
    rl_entry_t *e = get_or_create(ctx->client_ip, t); 
    if (!e) {
        LeaveCriticalSection(&g_rl_lock);
        return FILTER_OK; 
    }
    refill(e, t);
    if (e->tokens >= 1.0) {
        e->tokens -= 1.0;
        LeaveCriticalSection(&g_rl_lock);
        return FILTER_OK;
    } else {
        e->violate_count++;
        int count = e->violate_count;
        LeaveCriticalSection(&g_rl_lock);

        // Nếu vi phạm >= 5 lần => chặn 
        if (count >= 5) {
            acl_add(ctx->client_ip);
        }
        return FILTER_DENY;
    }
}

