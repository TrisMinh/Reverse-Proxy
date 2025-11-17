#ifndef DAO_METRICS_H
#define DAO_METRICS_H

#include "dbhelper.h"
#include "request_metrics.h"
#include <stdint.h>
#include <time.h>

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
);

int dao_metrics_insert_request_metrics_batch(
    request_counter_t *counters, 
    time_t timestamp,
    uint64_t domain_id,       
    const char *host           
);

int dao_metrics_insert_route_cache(
    time_t timestamp,
    uint64_t domain_id,        
    const char *host,         
    const char *route_path,
    uint64_t hit_count,
    uint64_t miss_count,
    uint64_t byte_hit,
    uint64_t byte_miss
);

uint64_t dao_metrics_lookup_domain_id(const char *host);

uint64_t dao_metrics_lookup_domain_id_by_id(uint64_t domain_id);

#endif // DAO_METRICS_H

