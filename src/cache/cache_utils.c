#include "../include/cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t fnv1a_hash(const char *key, size_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)key[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static void generate_fingerprint(const char *key, size_t len, char *fp_out) {
    uint64_t hash1 = fnv1a_hash(key, len);

    uint64_t hash2 = 0x811c9dc5ULL;  
    for (size_t i = 0; i < len; i++) {
        hash2 ^= (uint8_t)key[i];
        hash2 *= 0x01000193ULL;
    }

    memcpy(fp_out, &hash1, 8);
    memcpy(fp_out + 8, &hash2, 8);
}

static inline uint32_t hash_to_shard(uint64_t hash) {
    return (uint32_t)(hash & (CACHE_NUM_SHARDS - 1));
}

typedef struct {
    char *key;
    char *value;
    size_t key_len;
    size_t value_len;
} query_param_t;

static int compare_params(const void *a, const void *b) {
    const query_param_t *pa = (const query_param_t *)a;
    const query_param_t *pb = (const query_param_t *)b;
    size_t min_len = pa->key_len < pb->key_len ? pa->key_len : pb->key_len;
    int cmp = memcmp(pa->key, pb->key, min_len);
    if (cmp != 0) return cmp;
    return (int)(pa->key_len - pb->key_len);
}

static int normalize_query(const char *query, char *out, size_t out_size) {
    if (!query || out_size == 0) {
        if (out && out_size > 0) out[0] = '\0';
        return 0;
    }
    
    size_t query_len = strlen(query);
    if (query_len == 0) {
        if (out && out_size > 0) out[0] = '\0';
        return 0;
    }

    if (query_len >= out_size || query_len > 1024) {
        size_t copy_len = out_size - 1;
        if (query_len < copy_len) copy_len = query_len;
        memcpy(out, query, copy_len);
        out[copy_len] = '\0';
        return 0;
    }

    query_param_t params[64];
    int param_count = 0;
    char *query_copy = (char *)malloc(query_len + 1);
    if (!query_copy) {

        memcpy(out, query, query_len < (out_size - 1) ? query_len : (out_size - 1));
        out[query_len < (out_size - 1) ? query_len : (out_size - 1)] = '\0';
        return 0;
    }
    memcpy(query_copy, query, query_len + 1);

    char *saveptr = NULL;
    char *delim = "&";
    
    char *param = strtok_s(query_copy, delim, &saveptr);
    while (param_count < 64 && param) {

        char *eq = strchr(param, '=');
        if (eq) {
            *eq = '\0';
            params[param_count].key = param;
            params[param_count].key_len = strlen(param);
            params[param_count].value = eq + 1;
            params[param_count].value_len = strlen(params[param_count].value);
        } else {

            params[param_count].key = param;
            params[param_count].key_len = strlen(param);
            params[param_count].value = NULL;
            params[param_count].value_len = 0;
        }
        param_count++;
        param = strtok_s(NULL, delim, &saveptr);
    }

    if (param_count > 1) {
        qsort(params, param_count, sizeof(query_param_t), compare_params);
    }

    size_t pos = 0;
    for (int i = 0; i < param_count && pos < out_size - 1; i++) {
        if (i > 0) {
            if (pos < out_size - 1) out[pos++] = '&';
        }

        size_t key_copy = params[i].key_len;
        if (pos + key_copy >= out_size - 1) {
            key_copy = out_size - 1 - pos - 1;  
        }
        memcpy(out + pos, params[i].key, key_copy);
        pos += key_copy;

        if (params[i].value && params[i].value_len > 0) {
            if (pos < out_size - 1) out[pos++] = '=';
            size_t val_copy = params[i].value_len;
            if (pos + val_copy >= out_size - 1) {
                val_copy = out_size - 1 - pos;
            }
            memcpy(out + pos, params[i].value, val_copy);
            pos += val_copy;
        }
    }

    if (pos < out_size) {
        out[pos] = '\0';
    } else if (out_size > 0) {
        out[out_size - 1] = '\0';
    }
    
    free(query_copy);
    return 0;
}

int build_cache_key(const char *method, const char *scheme,
                   const char *host, const char *path, 
                   const char *query, const char *vary_header,
                   char *key_buf, size_t key_buf_size) {
    if (!key_buf || key_buf_size == 0) return -1;
    
    char norm_query[512] = {0};
    if (query && strlen(query) > 0) {
        normalize_query(query, norm_query, sizeof(norm_query));
    }
    
    const char *method_str = method ? method : "GET";
    const char *scheme_str = scheme ? scheme : "http";
    const char *host_str = host ? host : "";
    const char *path_str = path ? path : "/";
    const char *vary_str = vary_header ? vary_header : "";

    char query_part[513] = {0};
    if (norm_query[0]) {
        _snprintf(query_part, sizeof(query_part), "?%s", norm_query);
    }
    
    int n = _snprintf(key_buf, key_buf_size,
                     "%s:%s://%s%s%s|vary:%s",
                     method_str,
                     scheme_str,
                     host_str,
                     path_str,
                     query_part,
                     vary_str);
    
    if (n < 0 || (size_t)n >= key_buf_size) {
        key_buf[key_buf_size - 1] = '\0';
        return -1;
    }
    
    return 0;
}

void cache_key_hash(const char *key, uint64_t *hash_out, char *fingerprint_out) {
    if (!key || !hash_out || !fingerprint_out) return;
    
    size_t key_len = strlen(key);
    *hash_out = fnv1a_hash(key, key_len);
    generate_fingerprint(key, key_len, fingerprint_out);
}

uint32_t cache_key_to_shard(uint64_t key_hash) {
    return hash_to_shard(key_hash);
}

