#ifndef REQUEST_METRICS_H
#define REQUEST_METRICS_H

#include <stdint.h>
#include <time.h>

typedef struct request_counter_s {
    char route[512];         
    char method[10];          
    uint32_t status_code;      
    char status_category[4]; 
    char host[256];  
    uint64_t request_count;  
    uint64_t bytes_in;  
    uint64_t bytes_out;   
    uint64_t cache_hits;
    uint64_t cache_misses; 
    struct request_counter_s *next;  
} request_counter_t;

// Per-minute aggregated stats
typedef struct request_minute_stats_s {
    uint64_t total_requests; 
    uint64_t requests_2xx; 
    uint64_t requests_4xx;   
    uint64_t requests_5xx;  
    uint64_t total_bytes_in; 
    uint64_t total_bytes_out; 
    uint64_t total_cache_hits;  
    uint64_t total_cache_misses; 
    uint64_t peak_requests_min;
    time_t timestamp; 
} request_minute_stats_t;

int request_tracker_init(void);

void request_tracker_shutdown(void);

int request_tracker_record(
    const char *route,
    const char *method,
    uint32_t status_code,
    const char *host,
    uint64_t bytes_in,
    uint64_t bytes_out,
    int was_cache_hit
);

request_minute_stats_t* request_tracker_get_current_minute(void);

request_counter_t* request_tracker_get_snapshot(void);

void request_tracker_reset(void);

static inline const char* get_status_category(uint32_t status_code) {
    if (status_code >= 200 && status_code < 300) return "2xx";
    if (status_code >= 300 && status_code < 400) return "3xx";
    if (status_code >= 400 && status_code < 500) return "4xx";
    if (status_code >= 500) return "5xx";
    return "2xx";  
}

#endif 

