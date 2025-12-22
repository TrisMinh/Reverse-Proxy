
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/rate_limit.h"
#include "../include/acl_filter.h"

#define RL_DEFAULT_RATE   20.0  /* tokens per second */
#define RL_DEFAULT_BURST  200.0  /* max tokens */
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

// Hash IP + Domain để phân bucket
static unsigned hash_ip_domain(const char *ip, const char *domain) {
    unsigned h = 2166136261u;
    // Hash IP
    while (*ip) {
        h ^= (unsigned char)(*ip++);
        h *= 16777619u;
    }
    // Hash Domain
    if (domain && domain[0] != '\0') {
        while (*domain) {
            h ^= (unsigned char)(*domain++);
            h *= 16777619u;
        }
    }
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

static rl_entry_t *get_or_create(const char *ip, const char *domain, uint64_t now)
{
    unsigned idx = hash_ip_domain(ip, domain);
    rl_entry_t *prev = NULL, *e = g_buckets[idx];

    while (e) {
        // So sánh cả IP và Domain
        int ip_match = (strncmp(e->ip, ip, sizeof(e->ip)) == 0);
        int domain_match = 0;
        
        if (domain && domain[0] != '\0') {
            domain_match = (strncmp(e->domain, domain, sizeof(e->domain)) == 0);
        } else {
            domain_match = (e->domain[0] == '\0');
        }
        
        if (ip_match && domain_match) {
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

    // Tạo entry mới cho IP + Domain
    rl_entry_t *ne = (rl_entry_t*)calloc(1, sizeof(rl_entry_t));
    if (!ne) return NULL;
    
    strncpy(ne->ip, ip, sizeof(ne->ip) - 1);
    if (domain && domain[0] != '\0') {
        strncpy(ne->domain, domain, sizeof(ne->domain) - 1);
    } else {
        ne->domain[0] = '\0';
    }
    
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

    // Lấy domain từ context (bắt buộc phải có domain)
    const char *domain = (ctx->client_domain[0] != '\0') ? ctx->client_domain : NULL;
    if (!domain) {
        // Không có domain thì không rate limit
        printf("[Rate Limit] No domain, skipping rate limit\n");
        return FILTER_OK;
    }

    uint64_t t = now_ms();
    EnterCriticalSection(&g_rl_lock);
    
    // Tạo bucket riêng cho từng cặp (IP, Domain)
    rl_entry_t *e = get_or_create(ctx->client_ip, domain, t); 
    if (!e) {
        printf("[Rate Limit] Failed to create entry\n");
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

        // Chỉ add to blacklist 1 lần khi vi phạm đúng 5 lần
        if (count == 5) {
            printf("[Rate Limit] IP %s exceeded limit on domain %s (violate=%d), adding to blacklist\n",
                   ctx->client_ip, domain, count);
            acl_add(ctx->client_ip, domain);
        }
        return FILTER_DENY;
    }
}

