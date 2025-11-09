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

// Helper functions for proxy integration
typedef struct {
    uint64_t key_hash;
    char key_fingerprint[16];
    int should_cache;
} cache_key_info_t;

typedef struct {
    uint8_t *buffer;
    size_t size;
    size_t capacity;
    uint32_t status_code;
    char content_type[128];
    int complete;
} cache_buffer_t;

// Prepare cache key (hash + fingerprint) from request info
int cache_prepare_key(const char *method, const char *scheme,
                      const char *host, const char *path,
                      const char *query, const char *vary_header,
                      cache_key_info_t *key_info);

// Check if response should be cached based on conditions
int cache_should_cache_response(const char *method, uint32_t status_code,
                                int is_chunked, long long content_length,
                                uint32_t max_object_bytes);

// Initialize cache buffer
int cache_buffer_init(cache_buffer_t *buf, size_t capacity);

// Append data to cache buffer
int cache_buffer_append(cache_buffer_t *buf, const uint8_t *data, size_t len);

// Check if cache buffer is complete
int cache_buffer_is_complete(cache_buffer_t *buf, long long content_length);

// Free cache buffer
void cache_buffer_free(cache_buffer_t *buf);

// Try to store response in cache (with admission check and all logic)
int cache_try_store(const cache_key_info_t *key_info,
                   const cache_buffer_t *buf,
                   const char *method, const char *scheme,
                   const char *host, const char *path,
                   const char *query, const char *vary_header,
                   uint32_t ttl_seconds);

// Send cached response to client
int cache_send_response(void *client_fd, void *ssl, cache_value_t *cached_value);

// Handle cache hit: check expiry, send response, track metrics
// Returns: 1 if cache hit was valid and sent, 0 otherwise
int cache_handle_hit(void *client_fd, void *ssl, cache_value_t *cached_value,
                    const char *path, const char *query, const char *method,
                    const char *host, uint64_t bytes_in, uint64_t *bytes_out);

// Record request metrics (for cache miss)
void cache_record_metrics(const char *path, const char *query, const char *method,
                          uint32_t status_code, const char *host,
                          uint64_t bytes_in, uint64_t bytes_out, int was_cache_hit,
                          int cache_enabled);

// Extract request info (method, path, query, vary_header) from request buffer
int cache_extract_request_info(const char *request_buffer, char *method_out, size_t method_size,
                               char *path_out, size_t path_size, char *query_out, size_t query_size,
                               char *vary_header_out, size_t vary_size, int is_https);

// Process response headers: parse status, content-type, content-length, chunked
// Initialize cache buffer if response should be cached
// Returns: 0 on success, -1 on error
int cache_process_response_headers(const char *header_buf, int header_len, int body_len,
                                 const char *method, cache_key_info_t *key_info,
                                 cache_buffer_t *buf, uint32_t max_object_bytes,
                                 uint32_t *status_code_out, long long *content_length_out,
                                 int *is_chunked_out);

// Forward response chunk and append to cache buffer if needed
// Returns: bytes sent, or -1 on error
int cache_forward_response_chunk(void *client_fd, void *ssl, const uint8_t *data, size_t len,
                                cache_key_info_t *key_info, cache_buffer_t *buf);

#endif


