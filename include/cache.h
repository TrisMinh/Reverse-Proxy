#ifndef CACHE_H
#define CACHE_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define CACHE_MAX_OBJECT_BYTES 131072 
#define CACHE_DEFAULT_TTL_SEC 120
#define CACHE_NUM_SHARDS 64
#define CACHE_MAX_VARY_LEN 128
#define CACHE_DEFAULT_SECOND_HIT_WINDOW 10  
#define CACHE_BUCKETS_PER_SHARD 256 

typedef struct cache_value_s {
    uint8_t *body;
    uint32_t body_len;
    uint32_t status_code;
    char content_type[64]; 
    uint32_t expires_at; 
    char etag[64];
    char last_modified[64];
} cache_value_t;

typedef struct cache_entry_s {
    uint64_t key_hash; 
    char key_fingerprint[16]; 
    cache_value_t *val;
    struct cache_entry_s *hnext;  
    struct cache_entry_s *lru_prev; 
    struct cache_entry_s *lru_next;
    volatile LONG refcnt;  
    uint32_t created_at; 
} cache_entry_t;

typedef struct cache_shard_s {
    SRWLOCK lock;
    cache_entry_t **buckets; 
    uint32_t nbuckets;
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;
    uint64_t bytes_used; 
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t byte_hits; 
    uint64_t byte_misses; 
} cache_shard_t;

typedef struct second_hit_entry_s {
    uint64_t key_hash;
    char key_fingerprint[16];
    uint32_t first_seen_at; 
    struct second_hit_entry_s *hnext;
} second_hit_entry_t;

typedef struct second_hit_shard_s {
    SRWLOCK lock;
    second_hit_entry_t **buckets;
    uint32_t nbuckets;
} second_hit_shard_t;

typedef struct http_cache_s {
    cache_shard_t shards[CACHE_NUM_SHARDS];
    second_hit_shard_t hit_trackers[CACHE_NUM_SHARDS]; 
    uint64_t max_bytes;
    uint32_t default_ttl_sec;
    uint32_t second_hit_window_sec;
    uint8_t enabled;
} http_cache_t;

typedef enum {
    CACHE_RESULT_HIT = 1,
    CACHE_RESULT_MISS = 0,
    CACHE_RESULT_ERROR = -1
} cache_result_t;

int cache_init(uint64_t max_bytes, uint32_t default_ttl, uint32_t second_hit_window);
void cache_shutdown(void);

cache_result_t cache_get(const char *method, const char *scheme, 
                        const char *host, const char *path, 
                        const char *query, const char *vary_header,
                        cache_value_t **out);

int cache_put(const char *method, const char *scheme,
              const char *host, const char *path, const char *query,
              const char *vary_header, uint32_t status_code,
              const uint8_t *body, uint32_t body_len,
              const char *content_type, uint32_t ttl_seconds);

void cache_entry_release(cache_entry_t *entry);
void cache_evict_until_under(uint64_t max_bytes);

int cache_check_admission(uint64_t key_hash, const char *key_fingerprint);

void cache_get_metrics(uint64_t *hits, uint64_t *misses, uint64_t *evictions, uint64_t *bytes_used);
double cache_get_hit_rate(void);

void cache_get_egress_bytes(uint64_t *cached_bytes, uint64_t *missed_bytes);
double cache_get_byte_hit_rate(void);
double cache_get_offload_percent(uint64_t total_requests);
void cache_track_byte_miss(uint64_t bytes);

int build_cache_key(const char *method, const char *scheme,
                   const char *host, const char *path, 
                   const char *query, const char *vary_header,
                   char *key_buf, size_t key_buf_size);

void cache_key_hash(const char *key, uint64_t *hash_out, char *fingerprint_out);

uint32_t cache_key_to_shard(uint64_t key_hash);

uint64_t fnv1a_hash(const char *key, size_t len);

#endif


