#include "../include/cache.h"
#include "../include/logger.h"
#include <string.h>
#include <stdio.h>

int cache_check_has_authorization(const char *request_buffer) {
    if (!request_buffer) return 0;
    
    const char *auth_header = strstr(request_buffer, "Authorization:");
    if (!auth_header) {
        auth_header = strstr(request_buffer, "authorization:");
    }
    
    if (auth_header) {
        const char *header_end = strstr(request_buffer, "\r\n\r\n");
        if (header_end && auth_header < header_end) {
            return 1;
        }
    }
    
    return 0;
}

void cache_debug_log_auth_detected(const char *path) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Request has Authorization header - DISABLING cache for path=%.*s", 
            (int)path_len, path);
    log_message("INFO", debug_buf);
}

void cache_debug_log_cache_disabled(const char *path) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Cache DISABLED for path=%.*s (has Authorization header)", 
            (int)path_len, path);
    log_message("INFO", debug_buf);
}

void cache_debug_log_cache_hit(const char *path, uint32_t status_code, uint32_t body_len) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Cache HIT for path=%.*s, status=%u, body_len=%u", 
            (int)path_len, path, status_code, body_len);
    log_message("INFO", debug_buf);
}

void cache_debug_log_cache_miss(const char *path, int cache_result) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Cache MISS for path=%.*s (result=%d)", 
            (int)path_len, path, cache_result);
    log_message("INFO", debug_buf);
}

void cache_debug_log_prepare_key_failed(const char *path) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Failed to prepare cache key for path=%.*s", 
            (int)path_len, path);
    log_message("WARN", debug_buf);
}

void cache_debug_log_storing(const char *path, uint32_t status_code, size_t size) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Storing response in cache: path=%.*s, status=%u, size=%zu", 
            (int)path_len, path, status_code, size);
    log_message("INFO", debug_buf);
}

void cache_debug_log_store_failed(const char *path, int result) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] Failed to store in cache: path=%.*s (result=%d)", 
            (int)path_len, path, result);
    log_message("WARN", debug_buf);
}

void cache_debug_log_not_storing(const char *path, int should_cache, int complete, size_t size) {
    char debug_buf[512];
    size_t path_len = strlen(path);
    if (path_len > 200) path_len = 200;
    snprintf(debug_buf, sizeof(debug_buf), 
            "[CACHE_DEBUG] NOT storing in cache: path=%.*s (should_cache=%d, complete=%d, size=%zu)", 
            (int)path_len, path, should_cache, complete, size);
    log_message("INFO", debug_buf);
}

