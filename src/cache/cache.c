#include "../include/cache.h"
#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global cache instance
static http_cache_t g_cache;
static int g_cache_initialized = 0;

static uint32_t get_current_time(void) {
    return (uint32_t)time(NULL);
}

// Forward declaration for logging
static void log_cache_operation(const char *operation, const char *details);

static void lru_unlink(cache_shard_t *shard, cache_entry_t *entry) {
    if (!entry) return;
    
    if (entry->lru_prev) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        // This was head
        shard->lru_head = entry->lru_next;
    }
    
    if (entry->lru_next) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        shard->lru_tail = entry->lru_prev;
    }
    
    entry->lru_prev = NULL;
    entry->lru_next = NULL;
}

static void lru_add_to_head(cache_shard_t *shard, cache_entry_t *entry) {
    if (!entry) return;
    
    entry->lru_prev = NULL;
    entry->lru_next = shard->lru_head;
    
    if (shard->lru_head) {
        shard->lru_head->lru_prev = entry;
    } else {
        shard->lru_tail = entry;
    }
    
    shard->lru_head = entry;
}

static void lru_promote(cache_shard_t *shard, cache_entry_t *entry) {
    if (!entry) return;
    if (entry == shard->lru_head) return;
    
    lru_unlink(shard, entry);
    lru_add_to_head(shard, entry);
}

static cache_entry_t *lru_pop_tail(cache_shard_t *shard) {
    cache_entry_t *tail = shard->lru_tail;
    if (tail) {
        lru_unlink(shard, tail);
    }
    return tail;
}

static cache_entry_t *hash_table_find(cache_shard_t *shard, 
                                      uint64_t key_hash,
                                      const char *fingerprint) {
    if (!shard || !fingerprint) return NULL;
    
    uint32_t bucket_idx = (uint32_t)(key_hash % shard->nbuckets);
    cache_entry_t *entry = shard->buckets[bucket_idx];
    
    while (entry) {
        if (entry->key_hash == key_hash && 
            memcmp(entry->key_fingerprint, fingerprint, 16) == 0) {
            return entry;
        }
        entry = entry->hnext;
    }
    
    return NULL;
}

static void hash_table_remove(cache_shard_t *shard, cache_entry_t *entry) {
    if (!shard || !entry) return;
    
    uint32_t bucket_idx = (uint32_t)(entry->key_hash % shard->nbuckets);
    cache_entry_t **bucket = &shard->buckets[bucket_idx];
    
    cache_entry_t *prev = NULL;
    cache_entry_t *curr = *bucket;
    
    while (curr) {
        if (curr == entry) {
            if (prev) {
                prev->hnext = entry->hnext;
            } else {
                *bucket = entry->hnext;
            }
            entry->hnext = NULL;
            return;
        }
        prev = curr;
        curr = curr->hnext;
    }
}

static void hash_table_add(cache_shard_t *shard, cache_entry_t *entry) {
    if (!shard || !entry) return;
    
    uint32_t bucket_idx = (uint32_t)(entry->key_hash % shard->nbuckets);
    entry->hnext = shard->buckets[bucket_idx];
    shard->buckets[bucket_idx] = entry;
}
static int init_cache_shard(cache_shard_t *shard, uint32_t nbuckets) {
    if (!shard) return -1;
    
    memset(shard, 0, sizeof(cache_shard_t));
    InitializeSRWLock(&shard->lock);
    
    shard->nbuckets = nbuckets;
    shard->buckets = (cache_entry_t **)calloc(nbuckets, sizeof(cache_entry_t *));
    if (!shard->buckets) {
        return -1;
    }
    
    shard->lru_head = NULL;
    shard->lru_tail = NULL;
    shard->bytes_used = 0;
    shard->hits = 0;
    shard->misses = 0;
    shard->evictions = 0;
    shard->byte_hits = 0;
    shard->byte_misses = 0;
    
    return 0;
}

static void cleanup_cache_shard(cache_shard_t *shard) {
    if (!shard) return;
    
    AcquireSRWLockExclusive(&shard->lock);
    cache_entry_t *entry = shard->lru_head;
    while (entry) {
        cache_entry_t *next = entry->lru_next;
        
        if (entry->val) {
            if (entry->val->body) {
                free(entry->val->body);
            }
            free(entry->val);
        }
        free(entry);
        entry = next;
    }
    
    if (shard->buckets) {
        free(shard->buckets);
        shard->buckets = NULL;
    }
    
    ReleaseSRWLockExclusive(&shard->lock);
}

static int init_second_hit_shard(second_hit_shard_t *shard, uint32_t nbuckets) {
    if (!shard) return -1;
    
    memset(shard, 0, sizeof(second_hit_shard_t));
    InitializeSRWLock(&shard->lock);
    
    shard->nbuckets = nbuckets;
    shard->buckets = (second_hit_entry_t **)calloc(nbuckets, sizeof(second_hit_entry_t *));
    if (!shard->buckets) {
        return -1;
    }
    
    return 0;
}

static void cleanup_second_hit_shard(second_hit_shard_t *shard) {
    if (!shard) return;
    
    AcquireSRWLockExclusive(&shard->lock);
    for (uint32_t i = 0; i < shard->nbuckets; i++) {
        second_hit_entry_t *entry = shard->buckets[i];
        while (entry) {
            second_hit_entry_t *next = entry->hnext;
            free(entry);
            entry = next;
        }
        shard->buckets[i] = NULL;
    }
    
    if (shard->buckets) {
        free(shard->buckets);
        shard->buckets = NULL;
    }
    
    ReleaseSRWLockExclusive(&shard->lock);
}

int cache_init(uint64_t max_bytes, uint32_t default_ttl, uint32_t second_hit_window) {
    if (g_cache_initialized) {
        log_message("WARN", "Cache already initialized");
        return 0;
    }
    
    memset(&g_cache, 0, sizeof(g_cache));
    g_cache.max_bytes = max_bytes > 0 ? max_bytes : 268435456ULL;  // Default 256MB
    g_cache.default_ttl_sec = default_ttl > 0 ? default_ttl : CACHE_DEFAULT_TTL_SEC;
    g_cache.second_hit_window_sec = second_hit_window > 0 ? second_hit_window : CACHE_DEFAULT_SECOND_HIT_WINDOW;
    g_cache.enabled = 1;

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        if (init_cache_shard(&g_cache.shards[i], CACHE_BUCKETS_PER_SHARD) != 0) {
            log_message("ERROR", "Failed to initialize cache shard");
            for (int j = 0; j < i; j++) {
                cleanup_cache_shard(&g_cache.shards[j]);
            }
            return -1;
        }
    }

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        if (init_second_hit_shard(&g_cache.hit_trackers[i], CACHE_BUCKETS_PER_SHARD) != 0) {
            log_message("ERROR", "Failed to initialize second-hit tracker shard");
            // Cleanup
            for (int j = 0; j < CACHE_NUM_SHARDS; j++) {
                cleanup_cache_shard(&g_cache.shards[j]);
            }
            for (int j = 0; j < i; j++) {
                cleanup_second_hit_shard(&g_cache.hit_trackers[j]);
            }
            return -1;
        }
    }
    
    g_cache_initialized = 1;
    
    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), 
             "Cache initialized: max_bytes=%llu, ttl=%u, second_hit_window=%u",
             g_cache.max_bytes, g_cache.default_ttl_sec, g_cache.second_hit_window_sec);
    log_message("INFO", log_buf);
    
    return 0;
}

void cache_shutdown(void) {
    if (!g_cache_initialized) return;
    
    g_cache.enabled = 0;

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        cleanup_cache_shard(&g_cache.shards[i]);
    }

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        cleanup_second_hit_shard(&g_cache.hit_trackers[i]);
    }
    
    g_cache_initialized = 0;
    log_message("INFO", "Cache shutdown complete");
}

static void entry_acquire(cache_entry_t *entry) {
    if (!entry) return;
    InterlockedIncrement(&entry->refcnt);
}

void cache_entry_release(cache_entry_t *entry) {
    if (!entry) return;
    InterlockedDecrement(&entry->refcnt);
}

static second_hit_entry_t *tracker_find(second_hit_shard_t *shard,
                                         uint64_t key_hash,
                                         const char *fingerprint) {
    if (!shard || !fingerprint) return NULL;
    
    uint32_t bucket_idx = (uint32_t)(key_hash % shard->nbuckets);
    second_hit_entry_t *entry = shard->buckets[bucket_idx];
    
    while (entry) {
        if (entry->key_hash == key_hash &&
            memcmp(entry->key_fingerprint, fingerprint, 16) == 0) {
            return entry;
        }
        entry = entry->hnext;
    }
    
    return NULL;
}

static void tracker_add(second_hit_shard_t *shard,
                        uint64_t key_hash,
                        const char *fingerprint,
                        uint32_t first_seen_at) {
    if (!shard || !fingerprint) return;
    
    second_hit_entry_t *entry = (second_hit_entry_t *)calloc(1, sizeof(second_hit_entry_t));
    if (!entry) return;
    
    entry->key_hash = key_hash;
    memcpy(entry->key_fingerprint, fingerprint, 16);
    entry->first_seen_at = first_seen_at;
    
    uint32_t bucket_idx = (uint32_t)(key_hash % shard->nbuckets);
    entry->hnext = shard->buckets[bucket_idx];
    shard->buckets[bucket_idx] = entry;
}

static void cleanup_expired_tracker_entries(second_hit_shard_t *shard, uint32_t now, uint32_t window_sec) {
    if (!shard) return;
    
    int cleaned = 0;
    const int max_cleanup = 10;
    
    // Scan all buckets
    for (uint32_t i = 0; i < shard->nbuckets && cleaned < max_cleanup; i++) {
        second_hit_entry_t **bucket = &shard->buckets[i];
        second_hit_entry_t *prev = NULL;
        second_hit_entry_t *curr = *bucket;
        
        while (curr && cleaned < max_cleanup) {
            if (now - curr->first_seen_at > window_sec) {
                second_hit_entry_t *next = curr->hnext;
                if (prev) {
                    prev->hnext = next;
                } else {
                    *bucket = next;
                }
                free(curr);
                curr = next;
                cleaned++;
            } else {
                prev = curr;
                curr = curr->hnext;
            }
        }
    }
}

static void tracker_remove(second_hit_shard_t *shard, second_hit_entry_t *entry) {
    if (!shard || !entry) return;
    
    uint32_t bucket_idx = (uint32_t)(entry->key_hash % shard->nbuckets);
    second_hit_entry_t **bucket = &shard->buckets[bucket_idx];
    
    second_hit_entry_t *prev = NULL;
    second_hit_entry_t *curr = *bucket;
    
    while (curr) {
        if (curr == entry) {
            if (prev) {
                prev->hnext = entry->hnext;
            } else {
                *bucket = entry->hnext;
            }
            free(entry);
            return;
        }
        prev = curr;
        curr = curr->hnext;
    }
}

cache_result_t cache_get(const char *method, const char *scheme, 
                        const char *host, const char *path, 
                        const char *query, const char *vary_header,
                        cache_value_t **out) {
    if (!g_cache_initialized || !g_cache.enabled || !out) {
        return CACHE_RESULT_ERROR;
    }

    char key_buf[2048];
    if (build_cache_key(method, scheme, host, path, query, vary_header, 
                       key_buf, sizeof(key_buf)) != 0) {
        return CACHE_RESULT_ERROR;
    }

    uint64_t key_hash;
    char fingerprint[16];
    cache_key_hash(key_buf, &key_hash, fingerprint);

    uint32_t shard_idx = cache_key_to_shard(key_hash);
    cache_shard_t *shard = &g_cache.shards[shard_idx];

    AcquireSRWLockExclusive(&shard->lock);
    
    cache_entry_t *entry = hash_table_find(shard, key_hash, fingerprint);
    
    if (!entry) {
        // MISS
        shard->misses++;
        ReleaseSRWLockExclusive(&shard->lock);
        *out = NULL;
        return CACHE_RESULT_MISS;
    }

    uint32_t now = get_current_time();
    if (entry->val && now >= entry->val->expires_at) {
        // Expired - remove it
        hash_table_remove(shard, entry);
        lru_unlink(shard, entry);
        uint64_t entry_size = sizeof(cache_entry_t) + sizeof(cache_value_t);
        if (entry->val && entry->val->body) {
            entry_size += entry->val->body_len;
        }

        if (shard->bytes_used >= entry_size) {
            shard->bytes_used -= entry_size;
        } else {
            shard->bytes_used = 0;
        }
        
        if (entry->val) {
            if (entry->val->body) free(entry->val->body);
            free(entry->val);
        }
        free(entry);
        shard->misses++;
        ReleaseSRWLockExclusive(&shard->lock);
        *out = NULL;
        return CACHE_RESULT_MISS;
    }

    lru_promote(shard, entry);
    entry_acquire(entry);
    shard->hits++;

    if (entry->val && entry->val->body) {
        shard->byte_hits += entry->val->body_len;
    }
    
    ReleaseSRWLockExclusive(&shard->lock);
    
    *out = entry->val;

    static volatile LONG hit_log_counter = 0;
    if (InterlockedIncrement(&hit_log_counter) % 100 == 0) {
        uint64_t total_hits = 0, total_misses = 0, dummy_evict = 0, dummy_bytes = 0;
        cache_get_metrics(&total_hits, &total_misses, &dummy_evict, &dummy_bytes);
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "Cache HIT (total: %llu hits, %llu misses, %.1f%% hit rate)",
                 total_hits, total_misses, cache_get_hit_rate());
        log_cache_operation("HIT", log_buf);
    }
    
    return CACHE_RESULT_HIT;
}

static void evict_shard_until_under(cache_shard_t *shard, uint64_t target_bytes, int max_evictions) {
    if (!shard || target_bytes == 0) return;
    
    int evicted_count = 0;
    const int SAFETY_MAX_EVICTIONS = 100; 
    
    if (max_evictions > SAFETY_MAX_EVICTIONS) {
        max_evictions = SAFETY_MAX_EVICTIONS;
    }
    
    while (shard->bytes_used > target_bytes && 
           evicted_count < max_evictions && 
           shard->lru_tail) {
        
        cache_entry_t *evict_entry = lru_pop_tail(shard);
        if (!evict_entry) break;
        uint64_t entry_size = sizeof(cache_entry_t) + sizeof(cache_value_t);
        if (evict_entry->val && evict_entry->val->body) {
            entry_size += evict_entry->val->body_len;
        }
        hash_table_remove(shard, evict_entry);
        
        // Free memory
        if (evict_entry->val) {
            if (evict_entry->val->body) {
                free(evict_entry->val->body);
            }
            free(evict_entry->val);
        }
        free(evict_entry);
        if (shard->bytes_used >= entry_size) {
            shard->bytes_used -= entry_size;
        } else {
            shard->bytes_used = 0;
        }
        
        shard->evictions++;
        evicted_count++;
    }

    if (evicted_count > 0) {
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "Evicted %d entries, shard bytes_used now: %llu / %llu",
                 evicted_count, shard->bytes_used, target_bytes);
        log_cache_operation("EVICT", log_buf);
    }
}

int cache_put(const char *method, const char *scheme,
              const char *host, const char *path, const char *query,
              const char *vary_header, uint32_t status_code,
              const uint8_t *body, uint32_t body_len,
              const char *content_type, uint32_t ttl_seconds) {
    if (!g_cache_initialized || !g_cache.enabled) {
        return -1;
    }

    if (!body || body_len == 0 || body_len > CACHE_MAX_OBJECT_BYTES) {
        return -1;
    }

    char key_buf[2048];
    if (build_cache_key(method, scheme, host, path, query, vary_header,
                       key_buf, sizeof(key_buf)) != 0) {
        return -1;
    }

    uint64_t key_hash;
    char fingerprint[16];
    cache_key_hash(key_buf, &key_hash, fingerprint);

    uint32_t shard_idx = cache_key_to_shard(key_hash);
    cache_shard_t *shard = &g_cache.shards[shard_idx];
    
    AcquireSRWLockExclusive(&shard->lock);

    cache_entry_t *existing = hash_table_find(shard, key_hash, fingerprint);
    if (existing) {
        uint32_t old_body_len = existing->val ? existing->val->body_len : 0;
        
        if (existing->val && existing->val->body) {
            free(existing->val->body);
        }
        
        uint32_t now = get_current_time();
        existing->val->body = (uint8_t *)malloc(body_len);
        if (!existing->val->body) {
            ReleaseSRWLockExclusive(&shard->lock);
            return -1;
        }
        memcpy(existing->val->body, body, body_len);
        existing->val->body_len = body_len;
        existing->val->status_code = status_code;
        existing->val->expires_at = now + (ttl_seconds > 0 ? ttl_seconds : g_cache.default_ttl_sec);
        strncpy(existing->val->content_type, content_type ? content_type : "text/plain", 
                sizeof(existing->val->content_type) - 1);
        existing->val->content_type[sizeof(existing->val->content_type) - 1] = '\0';

        shard->bytes_used += (body_len - old_body_len);
        
        lru_promote(shard, existing);
        ReleaseSRWLockExclusive(&shard->lock);
        return 0;
    }

    cache_entry_t *entry = (cache_entry_t *)calloc(1, sizeof(cache_entry_t));
    if (!entry) {
        ReleaseSRWLockExclusive(&shard->lock);
        return -1;
    }
    
    cache_value_t *val = (cache_value_t *)calloc(1, sizeof(cache_value_t));
    if (!val) {
        free(entry);
        ReleaseSRWLockExclusive(&shard->lock);
        return -1;
    }
    
    val->body = (uint8_t *)malloc(body_len);
    if (!val->body) {
        free(val);
        free(entry);
        ReleaseSRWLockExclusive(&shard->lock);
        return -1;
    }
    
    memcpy(val->body, body, body_len);
    val->body_len = body_len;
    val->status_code = status_code;
    
    uint32_t now = get_current_time();
    val->expires_at = now + (ttl_seconds > 0 ? ttl_seconds : g_cache.default_ttl_sec);
    
    strncpy(val->content_type, content_type ? content_type : "text/plain",
            sizeof(val->content_type) - 1);
    val->content_type[sizeof(val->content_type) - 1] = '\0';
    
    entry->key_hash = key_hash;
    memcpy(entry->key_fingerprint, fingerprint, 16);
    entry->val = val;
    entry->refcnt = 0;
    entry->created_at = now;

    hash_table_add(shard, entry);
    lru_add_to_head(shard, entry);

    uint64_t entry_size = body_len + sizeof(cache_entry_t) + sizeof(cache_value_t);
    shard->bytes_used += entry_size;

    static volatile LONG put_log_counter = 0;
    if (InterlockedIncrement(&put_log_counter) % 50 == 0) {
        char log_buf[256];
        snprintf(log_buf, sizeof(log_buf), "Cached entry: %u bytes, shard bytes_used: %llu/%llu",
                 body_len, shard->bytes_used, g_cache.max_bytes / CACHE_NUM_SHARDS);
        log_cache_operation("PUT", log_buf);
    }

    uint64_t max_bytes_per_shard = g_cache.max_bytes / CACHE_NUM_SHARDS;
    if (shard->bytes_used > max_bytes_per_shard) {
        uint64_t target_bytes = max_bytes_per_shard * 90 / 100;
        evict_shard_until_under(shard, target_bytes, 10);
        if (shard->bytes_used > max_bytes_per_shard) {
            target_bytes = max_bytes_per_shard * 80 / 100;
            evict_shard_until_under(shard, target_bytes, 20);
        }
    }
    
    ReleaseSRWLockExclusive(&shard->lock);
    return 0;
}

void cache_evict_until_under(uint64_t max_bytes) {
    if (!g_cache_initialized || max_bytes == 0) return;
    
    uint64_t target_bytes = max_bytes;
    uint64_t max_bytes_per_shard = target_bytes / CACHE_NUM_SHARDS;
    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        cache_shard_t *shard = &g_cache.shards[i];
        
        AcquireSRWLockExclusive(&shard->lock);
        
        if (shard->bytes_used > max_bytes_per_shard) {
            uint64_t shard_target = max_bytes_per_shard * 90 / 100;
            int max_evictions = 10;
            evict_shard_until_under(shard, shard_target, max_evictions);
        }
        
        ReleaseSRWLockExclusive(&shard->lock);
    }
}

int cache_check_admission(uint64_t key_hash, const char *key_fingerprint) {
    if (!g_cache_initialized || !g_cache.enabled || !key_fingerprint) {
        return 0; 
    }
    uint32_t shard_idx = cache_key_to_shard(key_hash);
    second_hit_shard_t *tracker = &g_cache.hit_trackers[shard_idx];
    uint32_t now = get_current_time();
    
    AcquireSRWLockExclusive(&tracker->lock);
    cleanup_expired_tracker_entries(tracker, now, g_cache.second_hit_window_sec);
    
    second_hit_entry_t *entry = tracker_find(tracker, key_hash, key_fingerprint);
    int should_cache = 0;
    
    if (entry) {
        if (now - entry->first_seen_at <= g_cache.second_hit_window_sec) {
            should_cache = 1;
            tracker_remove(tracker, entry);
        } else {
            entry->first_seen_at = now;
        }
    } else {
        tracker_add(tracker, key_hash, key_fingerprint, now);
        should_cache = 0;
    }
    
    ReleaseSRWLockExclusive(&tracker->lock);
    return should_cache;
}

void cache_get_metrics(uint64_t *hits, uint64_t *misses, uint64_t *evictions, uint64_t *bytes_used) {
    if (!hits || !misses || !evictions || !bytes_used) return;
    
    *hits = 0;
    *misses = 0;
    *evictions = 0;
    *bytes_used = 0;
    
    if (!g_cache_initialized) return;

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        cache_shard_t *shard = &g_cache.shards[i];
        AcquireSRWLockShared(&shard->lock);
        *hits += shard->hits;
        *misses += shard->misses;
        *evictions += shard->evictions;
        *bytes_used += shard->bytes_used;
        ReleaseSRWLockShared(&shard->lock);
    }
}

double cache_get_hit_rate(void) {
    if (!g_cache_initialized) return 0.0;
    
    uint64_t total_hits = 0;
    uint64_t total_misses = 0;

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        cache_shard_t *shard = &g_cache.shards[i];
        AcquireSRWLockShared(&shard->lock);
        total_hits += shard->hits;
        total_misses += shard->misses;
        ReleaseSRWLockShared(&shard->lock);
    }
    
    uint64_t total_requests = total_hits + total_misses;
    if (total_requests == 0) {
        return 0.0; 
    }

    return ((double)total_hits / (double)total_requests) * 100.0;
}

void cache_get_egress_bytes(uint64_t *cached_bytes, uint64_t *missed_bytes) {
    if (!cached_bytes || !missed_bytes) return;
    
    *cached_bytes = 0;
    *missed_bytes = 0;
    
    if (!g_cache_initialized) return;

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        cache_shard_t *shard = &g_cache.shards[i];
        AcquireSRWLockShared(&shard->lock);
        *cached_bytes += shard->byte_hits;
        *missed_bytes += shard->byte_misses;
        ReleaseSRWLockShared(&shard->lock);
    }
}

double cache_get_byte_hit_rate(void) {
    if (!g_cache_initialized) return 0.0;
    
    uint64_t cached_bytes = 0;
    uint64_t missed_bytes = 0;
    cache_get_egress_bytes(&cached_bytes, &missed_bytes);
    
    uint64_t total_bytes = cached_bytes + missed_bytes;
    if (total_bytes == 0) {
        return 0.0; 
    }

    return ((double)cached_bytes / (double)total_bytes) * 100.0;
}

double cache_get_offload_percent(uint64_t total_requests) {
    if (!g_cache_initialized || total_requests == 0) {
        return 0.0;
    }
    
    uint64_t total_hits = 0;
    uint64_t total_misses = 0;

    for (int i = 0; i < CACHE_NUM_SHARDS; i++) {
        cache_shard_t *shard = &g_cache.shards[i];
        AcquireSRWLockShared(&shard->lock);
        total_hits += shard->hits;
        total_misses += shard->misses;
        ReleaseSRWLockShared(&shard->lock);
    }

    return ((double)total_hits / (double)total_requests) * 100.0;
}

void cache_track_byte_miss(uint64_t bytes) {
    if (!g_cache_initialized || bytes == 0) return;

    uint32_t shard_idx = (uint32_t)(bytes % CACHE_NUM_SHARDS);
    cache_shard_t *shard = &g_cache.shards[shard_idx];
    
    AcquireSRWLockExclusive(&shard->lock);
    shard->byte_misses += bytes;
    ReleaseSRWLockExclusive(&shard->lock);
}

int cache_invalidate(const char *method, const char *scheme,
                     const char *host, const char *path,
                     const char *query, const char *vary_header) {
    if (!g_cache_initialized || !g_cache.enabled) return -1;
    if (!method || !scheme || !host || !path) return -1;
    
    char key_buf[2048];
    if (build_cache_key(method, scheme, host, path, query, vary_header,
                       key_buf, sizeof(key_buf)) != 0) {
        return -1;
    }
    
    uint64_t key_hash;
    char fingerprint[16];
    cache_key_hash(key_buf, &key_hash, fingerprint);
    
    uint32_t shard_idx = cache_key_to_shard(key_hash);
    cache_shard_t *shard = &g_cache.shards[shard_idx];
    
    AcquireSRWLockExclusive(&shard->lock);
    
    cache_entry_t *entry = hash_table_find(shard, key_hash, fingerprint);
    
    if (entry) {
        // Remove from hash table
        hash_table_remove(shard, entry);
        // Remove from LRU
        lru_unlink(shard, entry);
        
        // Update metrics
        uint64_t entry_size = sizeof(cache_entry_t) + sizeof(cache_value_t);
        if (entry->val && entry->val->body) {
            entry_size += entry->val->body_len;
        }
        
        if (shard->bytes_used >= entry_size) {
            shard->bytes_used -= entry_size;
        } else {
            shard->bytes_used = 0;
        }
        
        // Free memory
        if (entry->val) {
            if (entry->val->body) free(entry->val->body);
            free(entry->val);
        }
        free(entry);
        
        ReleaseSRWLockExclusive(&shard->lock);
        return 0;
    }
    
    ReleaseSRWLockExclusive(&shard->lock);
    return -1; // Entry not found
}

static void log_cache_operation(const char *operation, const char *details) {
    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "[CACHE %s] %s", operation, details);
    log_message("INFO", log_buf);
}

