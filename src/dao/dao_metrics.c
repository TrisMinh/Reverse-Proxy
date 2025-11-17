#include "dao_metrics.h"
#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void format_datetime(time_t t, char *buf, size_t buf_size) {
    struct tm *tm_info = localtime(&t);
    if (!tm_info) {
        snprintf(buf, buf_size, "NOW()");
        return;
    }
    snprintf(buf, buf_size, "'%04d-%02d-%02d %02d:%02d:%02d'",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
}

static void escape_string(const char *input, char *output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        if (output && output_size > 0) output[0] = '\0';
        return;
    }
    
    size_t out_idx = 0;
    for (size_t i = 0; input[i] != '\0' && out_idx < output_size - 1; i++) {
        if (input[i] == '\\' || input[i] == '\'' || input[i] == '"') {
            if (out_idx < output_size - 2) {
                output[out_idx++] = '\\';
                output[out_idx++] = input[i];
            }
        } else {
            output[out_idx++] = input[i];
        }
    }
    output[out_idx] = '\0';
}

static int strcasecmp_local(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int c1 = *s1;
        int c2 = *s2;
        // Convert to lowercase for comparison
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return c1 - c2;
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

static const char* normalize_method(const char *method) {
    if (!method) return "OTHER";

    if (strcasecmp_local(method, "GET") == 0) return "GET";
    if (strcasecmp_local(method, "HEAD") == 0) return "HEAD";
    if (strcasecmp_local(method, "POST") == 0) return "POST";
    if (strcasecmp_local(method, "PUT") == 0) return "PUT";
    if (strcasecmp_local(method, "PATCH") == 0) return "PATCH";
    if (strcasecmp_local(method, "DELETE") == 0) return "DELETE";
    if (strcasecmp_local(method, "OPTIONS") == 0) return "OPTIONS";

    return "OTHER";
}

int dao_metrics_insert_minute_summary(
    time_t timestamp,
    uint64_t domain_id,
    uint64_t total_requests,
    uint64_t requests_2xx,
    uint64_t requests_4xx,
    uint64_t requests_5xx,
    uint64_t total_bytes_in,
    uint64_t total_bytes_out,
    uint64_t peak_requests_min
) {
    char datetime_buf[64];
    format_datetime(timestamp, datetime_buf, sizeof(datetime_buf));
    
    char query[1024]; 
    int n = snprintf(query, sizeof(query),
        "INSERT INTO request_minute_summary ("
        "timestamp, domain_id, total_requests, requests_2xx, requests_4xx, requests_5xx, "
        "total_bytes_in, total_bytes_out, peak_requests_min"
        ") VALUES ("
        "%s, %llu, %llu, %llu, %llu, %llu, "
        "%llu, %llu, %llu"
        ") ON DUPLICATE KEY UPDATE "
        "total_requests = VALUES(total_requests), "
        "requests_2xx = VALUES(requests_2xx), "
        "requests_4xx = VALUES(requests_4xx), "
        "requests_5xx = VALUES(requests_5xx), "
        "total_bytes_in = VALUES(total_bytes_in), "
        "total_bytes_out = VALUES(total_bytes_out), "
        "peak_requests_min = VALUES(peak_requests_min)",
        datetime_buf,
        (unsigned long long)domain_id,
        (unsigned long long)total_requests,
        (unsigned long long)requests_2xx,
        (unsigned long long)requests_4xx,
        (unsigned long long)requests_5xx,
        (unsigned long long)total_bytes_in,
        (unsigned long long)total_bytes_out,
        (unsigned long long)peak_requests_min
    );
    
    if (n < 0 || n >= (int)sizeof(query)) {
        log_message("ERROR", "dao_metrics_insert_minute_summary: query buffer overflow");
        return -1;
    }
    
    if (db_execute(query) != 0) {
        log_message("ERROR", "dao_metrics_insert_minute_summary: failed to insert");
        return -1;
    }

    static int insert_count = 0;
    if (insert_count < 3) {
        char log_buf[256];
        snprintf(log_buf, sizeof(log_buf), "[DAO_METRICS] Inserted summary: requests=%llu, 2xx=%llu, 4xx=%llu, 5xx=%llu",
                 (unsigned long long)total_requests, (unsigned long long)requests_2xx, 
                 (unsigned long long)requests_4xx, (unsigned long long)requests_5xx);
        log_message("INFO", log_buf);
        insert_count++;
    }
    
    return 0;
}

int dao_metrics_insert_request_metrics_batch(
    request_counter_t *counters,
    time_t timestamp,
    uint64_t domain_id,
    const char *host
) {
    if (!counters || !host) {
        return -1;
    }
    
    char datetime_buf[64];
    format_datetime(timestamp, datetime_buf, sizeof(datetime_buf));
    
    char host_escaped[512];
    escape_string(host, host_escaped, sizeof(host_escaped));
    
    int success_count = 0;
    int error_count = 0;

    request_counter_t *counter = counters;
    while (counter) {
        char route_escaped[1024];
        escape_string(counter->route, route_escaped, sizeof(route_escaped));
        const char *normalized_method = normalize_method(counter->method);
        
        char query[1024];
        int n = snprintf(query, sizeof(query),
            "INSERT INTO metrics_minute ("
            "ts_minute, domain_id, host, route_bucket, method, status_class, "
            "requests, bytes_in, bytes_out"
            ") VALUES ("
            "%s, %llu, '%s', '%s', '%s', '%s', "
            "%llu, %llu, %llu"
            ") ON DUPLICATE KEY UPDATE "
            "requests = requests + VALUES(requests), "
            "bytes_in = bytes_in + VALUES(bytes_in), "
            "bytes_out = bytes_out + VALUES(bytes_out)",
            datetime_buf,
            (unsigned long long)domain_id,
            host_escaped,
            route_escaped,
            normalized_method,
            counter->status_category,
            (unsigned long long)counter->request_count,
            (unsigned long long)counter->bytes_in,
            (unsigned long long)counter->bytes_out
        );
        
        if (n < 0 || n >= (int)sizeof(query)) {
            error_count++;
            log_message("WARN", "dao_metrics_insert_request_metrics_batch: query buffer overflow");
        } else {
            if (db_execute(query) == 0) {
                success_count++;
            } else {
                error_count++;
                log_message("WARN", "dao_metrics_insert_request_metrics_batch: failed to insert counter");
            }
        }
        
        counter = counter->next;
    }
    
    if (error_count > 0) {
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "dao_metrics_insert_request_metrics_batch: %d success, %d errors", 
                 success_count, error_count);
        log_message("WARN", log_buf);
    }
    
    return (error_count == 0) ? 0 : -1;
}

int dao_metrics_insert_route_cache(
    time_t timestamp,
    uint64_t domain_id,
    const char *host,
    const char *route_path,
    uint64_t hit_count,
    uint64_t miss_count,
    uint64_t byte_hit,
    uint64_t byte_miss
) {
    if (!host || !route_path) {
        return -1;
    }
    
    char datetime_buf[64];
    format_datetime(timestamp, datetime_buf, sizeof(datetime_buf));
    
    char host_escaped[512];
    escape_string(host, host_escaped, sizeof(host_escaped));
    
    char route_escaped[1024];
    escape_string(route_path, route_escaped, sizeof(route_escaped));
    
    char query[1024];
    int n = snprintf(query, sizeof(query),
        "INSERT INTO cache_stats_minute ("
        "ts_minute, domain_id, host, route_bucket, "
        "hit, miss, byte_hit, byte_miss"
        ") VALUES ("
        "%s, %llu, '%s', '%s', "
        "%llu, %llu, %llu, %llu"
        ") ON DUPLICATE KEY UPDATE "
        "hit = hit + VALUES(hit), "
        "miss = miss + VALUES(miss), "
        "byte_hit = byte_hit + VALUES(byte_hit), "
        "byte_miss = byte_miss + VALUES(byte_miss)",
        datetime_buf,
        (unsigned long long)domain_id,
        host_escaped,
        route_escaped,
        (unsigned long long)hit_count,
        (unsigned long long)miss_count,
        (unsigned long long)byte_hit,
        (unsigned long long)byte_miss
    );
    
    if (n < 0 || n >= (int)sizeof(query)) {
        log_message("ERROR", "dao_metrics_insert_route_cache: query buffer overflow");
        return -1;
    }
    
    if (db_execute(query) != 0) {
        log_message("ERROR", "dao_metrics_insert_route_cache: failed to insert");
        return -1;
    }
    
    return 0;
}

uint64_t dao_metrics_lookup_domain_id(const char *host) {
    if (!host || strlen(host) == 0) {
        return 0;
    }

    char escaped_host[512];
    escape_string(host, escaped_host, sizeof(escaped_host));

    char query[1024];
    int n = snprintf(query, sizeof(query),
        "SELECT id FROM domains WHERE domain = '%s' AND status = 'active' LIMIT 1",
        escaped_host
    );
    
    if (n < 0 || n >= (int)sizeof(query)) {
        log_message("ERROR", "dao_metrics_lookup_domain_id: query buffer overflow");
        return 0;
    }
 
    static int lookup_count = 0;
    if (lookup_count < 3) {
        char host_trunc[128];
        char escaped_trunc[128];
        strncpy(host_trunc, host, sizeof(host_trunc) - 1);
        host_trunc[sizeof(host_trunc) - 1] = '\0';
        strncpy(escaped_trunc, escaped_host, sizeof(escaped_trunc) - 1);
        escaped_trunc[sizeof(escaped_trunc) - 1] = '\0';
        
        char debug_buf1[384];
        snprintf(debug_buf1, sizeof(debug_buf1), "[DAO_METRICS] Lookup domain_id for host='%.100s' (escaped='%.100s')", 
                host_trunc, escaped_trunc);
        log_message("INFO", debug_buf1);
        
        char query_trunc[400];
        size_t query_len = strlen(query);
        if (query_len > 350) {
            strncpy(query_trunc, query, 350);
            query_trunc[350] = '\0';
            strcat(query_trunc, "...");
        } else {
            strncpy(query_trunc, query, sizeof(query_trunc) - 1);
            query_trunc[sizeof(query_trunc) - 1] = '\0';
        }
        char debug_buf3[512];
        snprintf(debug_buf3, sizeof(debug_buf3), "[DAO_METRICS] Query: %.400s", query_trunc);
        log_message("INFO", debug_buf3);
        lookup_count++;
    }

    MYSQL_RES *result = db_query(query);
    if (!result) {
        char warn_buf[256];
        snprintf(warn_buf, sizeof(warn_buf), "[DAO_METRICS] Lookup failed for host='%s' - domain not found or query error", host);
        log_message("WARN", warn_buf);
        return 0;
    }
    
    // Get first row
    MYSQL_ROW row = mysql_fetch_row(result);
    uint64_t domain_id = 0;
    
    if (row && row[0]) {
        domain_id = strtoull(row[0], NULL, 10);
        if (lookup_count < 3) {
            char debug_buf[256];
            snprintf(debug_buf, sizeof(debug_buf), "[DAO_METRICS] Found domain_id=%llu for host='%s'", 
                    (unsigned long long)domain_id, host);
            log_message("INFO", debug_buf);
        }
    } else {
        char debug_buf[256];
        snprintf(debug_buf, sizeof(debug_buf), "[DAO_METRICS] No domain found for host='%s'", host);
        log_message("INFO", debug_buf);
    }
    
    mysql_free_result(result);
    
    return domain_id;
}

uint64_t dao_metrics_lookup_domain_id_by_id(uint64_t domain_id) {
    if (domain_id == 0) {
        return 0;
    }

    char query[256];
    int n = snprintf(query, sizeof(query),
        "SELECT id FROM domains WHERE id = %llu AND status = 'active' LIMIT 1",
        (unsigned long long)domain_id
    );
    
    if (n < 0 || n >= (int)sizeof(query)) {
        log_message("ERROR", "dao_metrics_lookup_domain_id_by_id: query buffer overflow");
        return 0;
    }

    MYSQL_RES *result = db_query(query);
    if (!result) {
        return 0;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    uint64_t found_id = 0;
    
    if (row && row[0]) {
        found_id = strtoull(row[0], NULL, 10);
    }
    
    mysql_free_result(result);
    
    return found_id;
}

