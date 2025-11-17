#include <winsock2.h>
#include <openssl/ssl.h>
#include "../include/cache.h"
#include "../include/logger.h"
#include "../include/request_metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <time.h>

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
int cache_prepare_key(const char *method, const char *scheme,
                      const char *host, const char *path,
                      const char *query, const char *vary_header,
                      cache_key_info_t *key_info) {
    if (!key_info) return -1;
    
    memset(key_info, 0, sizeof(cache_key_info_t));
    
    char key_buf[2048];
    if (build_cache_key(method, scheme, host, path, query, vary_header,
                       key_buf, sizeof(key_buf)) != 0) {
        return -1;
    }
    
    cache_key_hash(key_buf, &key_info->key_hash, key_info->key_fingerprint);
    key_info->should_cache = 1;
    
    return 0;
}

int cache_should_cache_response(const char *method, uint32_t status_code,
                                int is_chunked, long long content_length,
                                uint32_t max_object_bytes) {
    if (!method || strcmp(method, "GET") != 0) {
        return 0;
    }
    
    if (status_code != 200) {
        return 0;
    }
    
    if (is_chunked) {
        return 0;
    }
    
    if (content_length < 0) {
        return 0;
    }
    
    if (content_length > (long long)max_object_bytes) {
        return 0;
    }
    
    return 1;
}

int cache_buffer_init(cache_buffer_t *buf, size_t capacity) {
    if (!buf || capacity == 0) return -1;
    
    memset(buf, 0, sizeof(cache_buffer_t));
    buf->capacity = capacity;
    
    if (capacity > 0) {
        buf->buffer = (uint8_t *)malloc(capacity);
        if (!buf->buffer) {
            return -1;
        }
    }
    
    return 0;
}

int cache_buffer_append(cache_buffer_t *buf, const uint8_t *data, size_t len) {
    if (!buf || !data || len == 0) return -1;
    if (!buf->buffer) return -1;
    
    if (buf->size + len > buf->capacity) {
        return -1;
    }
    
    memcpy(buf->buffer + buf->size, data, len);
    buf->size += len;
    
    return 0;
}

int cache_buffer_is_complete(cache_buffer_t *buf, long long content_length) {
    if (!buf) return 0;
    if (content_length < 0) return 0;
    
    if (buf->size == (size_t)content_length && buf->size == buf->capacity) {
        buf->complete = 1;
        return 1;
    }
    
    return 0;
}

void cache_buffer_free(cache_buffer_t *buf) {
    if (!buf) return;
    
    if (buf->buffer) {
        free(buf->buffer);
        buf->buffer = NULL;
    }
    
    memset(buf, 0, sizeof(cache_buffer_t));
}

int cache_try_store(const cache_key_info_t *key_info,
                   const cache_buffer_t *buf,
                   const char *method, const char *scheme,
                   const char *host, const char *path,
                   const char *query, const char *vary_header,
                   uint32_t ttl_seconds) {
    if (!key_info || !buf) {
        char debug_buf[256];
        snprintf(debug_buf, sizeof(debug_buf), 
                "[CACHE_DEBUG] cache_try_store: Invalid parameters (key_info=%p, buf=%p)", 
                (void*)key_info, (void*)buf);
        log_message("WARN", debug_buf);
        return -1;
    }
    if (!key_info->should_cache) {
        char debug_buf[512];
        size_t path_len = strlen(path ? path : "");
        if (path_len > 150) path_len = 150;
        snprintf(debug_buf, sizeof(debug_buf), 
                "[CACHE_DEBUG] NOT cached: path=%.*s (should_cache=0)", 
                (int)path_len, path ? path : "");
        log_message("INFO", debug_buf);
        return -1;
    }
    if (!buf->complete || buf->size == 0) {
        char debug_buf[512];
        size_t path_len = strlen(path ? path : "");
        if (path_len > 150) path_len = 150;
        snprintf(debug_buf, sizeof(debug_buf), 
                "[CACHE_DEBUG] NOT cached: path=%.*s (buffer incomplete: complete=%d, size=%zu)", 
                (int)path_len, path ? path : "", buf->complete, buf->size);
        log_message("INFO", debug_buf);
        return -1;
    }

    int should_cache = cache_check_admission(key_info->key_hash, key_info->key_fingerprint);
    if (!should_cache) {
        static int debug_count = 0;
        if (debug_count < 10) {
            char debug_buf[512];
            size_t path_len = strlen(path ? path : "");
            if (path_len > 150) path_len = 150;
            snprintf(debug_buf, sizeof(debug_buf), 
                    "[CACHE_DEBUG] NOT cached: path=%.*s, admission=%d (need 2nd hit in window)", 
                    (int)path_len, path ? path : "", should_cache);
            log_message("INFO", debug_buf);
            debug_count++;
        }
        return -1;
    }

    char debug_buf[512];
    size_t path_len = strlen(path ? path : "");
    if (path_len > 150) path_len = 150;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Attempting to store: path=%.*s, status=%u, size=%zu, ttl=%u", 
            (int)path_len, path ? path : "", buf->status_code, buf->size, ttl_seconds);
    log_message("INFO", debug_buf);

    int result = cache_put(method, scheme, host, path, query, vary_header,
                          buf->status_code,
                          buf->buffer, (uint32_t)buf->size,
                          buf->content_type[0] ? buf->content_type : "text/html",
                          ttl_seconds);
    
    if (result == 0) {
        char log_buf[512];
        size_t query_len = query ? strlen(query) : 0;
        if (query_len > 50) query_len = 50;
        snprintf(log_buf, sizeof(log_buf), "[CACHE_DEBUG] Successfully cached: path=%.*s%.*s (status=%u, size=%llu, ttl=%u)", 
                (int)path_len, path ? path : "", 
                (int)query_len, query ? query : "",
                buf->status_code,
                (unsigned long long)buf->size, ttl_seconds);
        log_message("INFO", log_buf);
    } else {
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), 
                "[CACHE_DEBUG] Failed to cache: path=%.*s (cache_put returned %d)", 
                (int)path_len, path ? path : "", result);
        log_message("WARN", log_buf);
    }
    
    return result;
}

static int send_all_data(void *sock, const char *buf, int len, void *ssl) {
    SOCKET fd = (SOCKET)(uintptr_t)sock;
    SSL *ssl_ptr = (SSL *)ssl;
    
    int sent = 0;
    while (sent < len) {
        int n = ssl_ptr ? SSL_write(ssl_ptr, buf + sent, len - sent)
                       : send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

int cache_send_response(void *client_fd, void *ssl, cache_value_t *cached_value) {
    if (!cached_value || !client_fd) return -1;
    
    uint32_t now = (uint32_t)time(NULL);
    if (now >= cached_value->expires_at) {
        return -1;
    }
    
    uint32_t max_age = cached_value->expires_at - now;
    uint32_t age = max_age;

    char response_header[4096];
    int n = snprintf(response_header, sizeof(response_header),
        "HTTP/1.1 %u %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: public, max-age=%u\r\n"
        "Age: %u\r\n"
        "X-Cache: HIT\r\n"
        "Connection: close\r\n"
        "\r\n",
        cached_value->status_code,
        cached_value->status_code == 200 ? "OK" : 
        cached_value->status_code == 404 ? "Not Found" :
        cached_value->status_code == 304 ? "Not Modified" : "OK",
        cached_value->content_type[0] ? cached_value->content_type : "text/html",
        cached_value->body_len,
        max_age,
        age);
    
    if (n > 0 && n < (int)sizeof(response_header)) {
        if (send_all_data(client_fd, response_header, n, ssl) != 0) {
            return -1;
        }
        if (cached_value->body && cached_value->body_len > 0) {
            if (send_all_data(client_fd, (const char *)cached_value->body, cached_value->body_len, ssl) != 0) {
                return -1;
            }
        }
        return 0;
    }
    
    return -1;
}

static void build_route_string(const char *path, const char *query, char *route_out, size_t route_size) {
    if (!route_out || route_size == 0) return;
    
    route_out[0] = '\0';
    if (!path) path = "/";
    
    size_t path_len = strlen(path);
    if (path_len > 400) path_len = 400;
    
    size_t query_len = query && query[0] ? strlen(query) : 0;
    if (query_len > 100) query_len = 100;
    
    if (query && query_len > 0) {
        snprintf(route_out, route_size, "%.*s?%.*s", 
                (int)path_len, path, (int)query_len, query);
    } else {
        snprintf(route_out, route_size, "%.*s", (int)path_len, path);
    }
    route_out[route_size - 1] = '\0';
}

int cache_handle_hit(void *client_fd, void *ssl, cache_value_t *cached_value,
                    const char *path, const char *query, const char *method,
                    const char *host, uint64_t bytes_in, uint64_t *bytes_out) {
    if (!cached_value || !client_fd || !bytes_out) return 0;
    
    uint32_t now = (uint32_t)time(NULL);
    if (now >= cached_value->expires_at) {
        return 0;
    }

    if (cache_send_response(client_fd, ssl, cached_value) != 0) {
        return 0;
    }

    *bytes_out = (uint64_t)cached_value->body_len;

    char route[512];
    build_route_string(path, query, route, sizeof(route));
    request_tracker_record(route, method ? method : "GET", 
                          cached_value->status_code, 
                          host ? host : "", 
                          bytes_in, *bytes_out, 1);
    
    return 1; 
}

void cache_record_metrics(const char *path, const char *query, const char *method,
                          uint32_t status_code, const char *host,
                          uint64_t bytes_in, uint64_t bytes_out, int was_cache_hit,
                          int cache_enabled) {
    if (!path) path = "/";
    if (!method) method = "GET";
    if (!host) host = "";
    if (status_code == 0) status_code = 200;

    if (!was_cache_hit && cache_enabled && bytes_out > 0) {
        if (strcmp(method, "GET") == 0) {
            cache_track_byte_miss(bytes_out);
        }
    }

    char route[512];
    build_route_string(path, query, route, sizeof(route));
    request_tracker_record(route, method, status_code, host, bytes_in, bytes_out, was_cache_hit);
}

int cache_extract_request_info(const char *request_buffer, char *method_out, size_t method_size,
                               char *path_out, size_t path_size, char *query_out, size_t query_size,
                               char *vary_header_out, size_t vary_size, int is_https) {
    if (!request_buffer || !method_out || !path_out || !query_out || !vary_header_out) {
        return -1;
    }
    
    // Extract method
    const char *space = strchr(request_buffer, ' ');
    if (!space) {
        strncpy(method_out, "GET", method_size - 1);
        method_out[method_size - 1] = '\0';
    } else {
        size_t len = space - request_buffer;
        if (len >= method_size) len = method_size - 1;
        memcpy(method_out, request_buffer, len);
        method_out[len] = '\0';
    }

    const char *sp1 = strchr(request_buffer, ' ');
    if (!sp1) return -1;
    const char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) return -1;
    
    size_t uri_len = sp2 - (sp1 + 1);
    if (uri_len == 0) return -1;
    
    const char *qmark = memchr(sp1 + 1, '?', uri_len);
    if (qmark && qmark < sp2) {
        size_t path_len = qmark - (sp1 + 1);
        size_t query_len = sp2 - (qmark + 1);
        
        if (path_len > 0 && path_len < path_size) {
            memcpy(path_out, sp1 + 1, path_len);
            path_out[path_len] = '\0';
        } else if (path_len == 0) {
            strncpy(path_out, "/", path_size - 1);
            path_out[path_size - 1] = '\0';
        }
        
        if (query_len > 0 && query_len < query_size) {
            memcpy(query_out, qmark + 1, query_len);
            query_out[query_len] = '\0';
        }
    } else {
        if (uri_len < path_size) {
            memcpy(path_out, sp1 + 1, uri_len);
            path_out[uri_len] = '\0';
        }
    }
    
    if (path_out[0] == '\0') {
        strncpy(path_out, "/", path_size - 1);
        path_out[path_size - 1] = '\0';
    }

    vary_header_out[0] = '\0';
    const char *header_end = strstr(request_buffer, "\r\n\r\n");
    if (header_end) {
        const char *ae = strstr(request_buffer, "Accept-Encoding:");
        if (!ae) {
            ae = strstr(request_buffer, "accept-encoding:");
        }
        if (ae && ae < header_end) {
            ae += 15;
            while (*ae == ' ' || *ae == '\t') ae++;
            const char *line_end = strstr(ae, "\r\n");
            if (!line_end) line_end = header_end;
            size_t len = line_end - ae;
            if (len > 0 && len < vary_size) {
                memcpy(vary_header_out, ae, len);
                vary_header_out[len] = '\0';
                // Trim trailing whitespace
                while (len > 0 && (vary_header_out[len - 1] == ' ' || 
                                  vary_header_out[len - 1] == '\t' || 
                                  vary_header_out[len - 1] == '\r')) {
                    vary_header_out[--len] = '\0';
                }
            }
        }
    }
    
    return 0;
}

int cache_process_response_headers(const char *header_buf, int header_len, int body_len,
                                 const char *method, cache_key_info_t *key_info,
                                 cache_buffer_t *buf, uint32_t max_object_bytes,
                                 uint32_t *status_code_out, long long *content_length_out,
                                 int *is_chunked_out) {
    if (!header_buf || !buf || !status_code_out || !content_length_out || !is_chunked_out) {
        return -1;
    }
    
    const char *hdr_end = strstr(header_buf, "\r\n\r\n");
    if (!hdr_end) return -1;

    if (strncmp(header_buf, "HTTP/", 5) == 0) {
        const char *sp = strchr(header_buf + 5, ' ');
        if (sp) {
            *status_code_out = (uint32_t)atoi(sp + 1);
            buf->status_code = *status_code_out;
        }
    }

    *content_length_out = -1;
    const char *cl = strstr(header_buf, "Content-Length:");
    if (!cl) cl = strstr(header_buf, "content-length:");
    if (cl && cl < hdr_end) {
        *content_length_out = atoll(cl + 15);
    }

    *is_chunked_out = 0;
    const char *te = strstr(header_buf, "Transfer-Encoding:");
    if (!te) te = strstr(header_buf, "transfer-encoding:");
    if (te && te < hdr_end && strstr(te, "chunked")) {
        *is_chunked_out = 1;
    }

    const char *ct = strstr(header_buf, "Content-Type:");
    if (!ct) ct = strstr(header_buf, "content-type:");
    if (ct && ct < hdr_end) {
        const char *ct_val = ct + 13;
        while (*ct_val == ' ' || *ct_val == '\t') ct_val++;
        const char *ct_end = strstr(ct_val, "\r\n");
        if (!ct_end) ct_end = hdr_end;
        size_t ct_len = ct_end - ct_val;
        if (ct_len >= sizeof(buf->content_type)) ct_len = sizeof(buf->content_type) - 1;
        memcpy(buf->content_type, ct_val, ct_len);
        buf->content_type[ct_len] = '\0';
    } else {
        strncpy(buf->content_type, "text/html", sizeof(buf->content_type) - 1);
        buf->content_type[sizeof(buf->content_type) - 1] = '\0';
    }

    if (key_info && key_info->should_cache && method) {
        if (cache_should_cache_response(method, *status_code_out, *is_chunked_out,
                                       *content_length_out, max_object_bytes)) {
            if (cache_buffer_init(buf, (size_t)(*content_length_out > 0 ? *content_length_out : 0)) != 0) {
                key_info->should_cache = 0;
            }
        } else {
            key_info->should_cache = 0;
        }
    }
    
    return 0;
}

int cache_forward_response_chunk(void *client_fd, void *ssl, const uint8_t *data, size_t len,
                                cache_key_info_t *key_info, cache_buffer_t *buf) {
    if (!client_fd || !data || len == 0) return -1;
    
    SOCKET fd = (SOCKET)(uintptr_t)client_fd;
    SSL *ssl_ptr = (SSL *)ssl;

    int sent = 0;
    while (sent < (int)len) {
        int n = ssl_ptr ? SSL_write(ssl_ptr, (const char *)data + sent, (int)len - sent)
                       : send(fd, (const char *)data + sent, (int)len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }

    if (key_info && key_info->should_cache && buf && buf->buffer) {
        cache_buffer_append(buf, data, len);
    }
    
    return sent;
}

