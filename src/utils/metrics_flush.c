#include "../include/metrics_flush.h"
#include "../include/request_metrics.h"
#include "../include/cache.h"
#include "../include/dao_metrics.h"
#include "../include/dbhelper.h"
#include "../include/db_config.h"
#include "../include/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <process.h>

// Thread state
static HANDLE g_flush_thread = NULL;
static volatile LONG g_flush_running = 0;
static volatile LONG g_flush_stop = 0;
static int flush_metrics_to_db(time_t minute_timestamp) {

    request_counter_t *counters = request_tracker_get_snapshot();

    request_minute_stats_t *minute_stats = request_tracker_get_current_minute();
    if (!minute_stats) {
        log_message("WARN", "[METRICS_FLUSH] minute_stats is NULL");
        while (counters) {
            request_counter_t *next = counters->next;
            free(counters);
            counters = next;
        }
        return -1;
    }
    char log_buf[256];
    int counter_count = 0;
    request_counter_t *tmp = counters;
    while (tmp) {
        counter_count++;
        tmp = tmp->next;
    }
    snprintf(log_buf, sizeof(log_buf), "[METRICS_FLUSH] Flushing: total_requests=%llu, counters=%d, timestamp=%lld",
             (unsigned long long)minute_stats->total_requests, counter_count, (long long)minute_timestamp);
    log_message("INFO", log_buf);
    
    if (minute_stats->total_requests == 0 && counter_count == 0) {
        log_message("INFO", "[METRICS_FLUSH] No data to flush, skipping");
        return 0;
    }
    time_t flush_timestamp = minute_timestamp;
    if (flush_timestamp == 0) {
        flush_timestamp = minute_stats->timestamp;
    }
    
    int success_count = 0;
    int error_count = 0;
    #define MAX_HOSTS 64
    char unique_hosts[MAX_HOSTS][256];
    uint64_t host_domain_ids[MAX_HOSTS];
    int host_count = 0;
    
    if (counters) {
        request_counter_t *counter = counters;
        while (counter && host_count < MAX_HOSTS) {
            const char *host = counter->host[0] ? counter->host : "default";

            int found = 0;
            for (int i = 0; i < host_count; i++) {
                if (strcmp(unique_hosts[i], host) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                strncpy(unique_hosts[host_count], host, sizeof(unique_hosts[host_count]) - 1);
                unique_hosts[host_count][sizeof(unique_hosts[host_count]) - 1] = '\0';

                uint64_t domain_id = dao_metrics_lookup_domain_id(host);
                if (domain_id == 0) {
                    uint64_t default_id = dao_metrics_lookup_domain_id_by_id(1);
                    if (default_id == 0) {
                        char error_buf[512];
                        snprintf(error_buf, sizeof(error_buf), 
                                "[METRICS_FLUSH] Domain '%s' not found in DB AND domain_id=1 does not exist. Metrics will be skipped for this host.", host);
                        log_message("ERROR", error_buf);
                        continue;
                    }
                    domain_id = 1;
                    char warn_buf[512];
                    snprintf(warn_buf, sizeof(warn_buf), "[METRICS_FLUSH] Domain '%s' not found in DB, using domain_id=1", host);
                    log_message("WARN", warn_buf);
                }
                host_domain_ids[host_count] = domain_id;
                host_count++;
            }
            
            counter = counter->next;
        }
    }
    if (host_count == 0) {
        strncpy(unique_hosts[0], "default", sizeof(unique_hosts[0]) - 1);
        host_domain_ids[0] = 1;
        host_count = 1;
    }
    for (int h = 0; h < host_count; h++) {
        const char *host = unique_hosts[h];
        uint64_t domain_id = host_domain_ids[h];
        uint64_t domain_total_requests = 0;
        uint64_t domain_requests_2xx = 0;
        uint64_t domain_requests_4xx = 0;
        uint64_t domain_requests_5xx = 0;
        uint64_t domain_total_bytes_in = 0;
        uint64_t domain_total_bytes_out = 0;
        uint64_t domain_peak_requests = 0;

        request_counter_t *domain_counters = NULL;
        request_counter_t *domain_counters_tail = NULL;
        
        if (counters) {
            request_counter_t *counter = counters;
            while (counter) {
                const char *counter_host = counter->host[0] ? counter->host : "default";
                
                if (strcmp(counter_host, host) == 0) {
                    domain_total_requests += counter->request_count;
                    domain_total_bytes_in += counter->bytes_in;
                    domain_total_bytes_out += counter->bytes_out;

                    if (strcmp(counter->status_category, "2xx") == 0) {
                        domain_requests_2xx += counter->request_count;
                    } else if (strcmp(counter->status_category, "4xx") == 0) {
                        domain_requests_4xx += counter->request_count;
                    } else if (strcmp(counter->status_category, "5xx") == 0) {
                        domain_requests_5xx += counter->request_count;
                    }
                    
                    if (counter->request_count > domain_peak_requests) {
                        domain_peak_requests = counter->request_count;
                    }

                    request_counter_t *copy = (request_counter_t*)malloc(sizeof(request_counter_t));
                    if (copy) {
                        memcpy(copy, counter, sizeof(request_counter_t));
                        copy->next = NULL;
                        
                        if (!domain_counters) {
                            domain_counters = copy;
                            domain_counters_tail = copy;
                        } else {
                            domain_counters_tail->next = copy;
                            domain_counters_tail = copy;
                        }
                    }
                }
                
                counter = counter->next;
            }
        }

        if (domain_total_requests == 0 && !domain_counters) {
            continue;
        }
        if (dao_metrics_insert_minute_summary(
                flush_timestamp,
                domain_id,
                domain_total_requests,
                domain_requests_2xx,
                domain_requests_4xx,
                domain_requests_5xx,
                domain_total_bytes_in,
                domain_total_bytes_out,
                domain_peak_requests) == 0) {
            success_count++;
        } else {
            error_count++;
            char err_buf[256];
            snprintf(err_buf, sizeof(err_buf), "metrics_flush: failed to insert minute summary for domain_id=%llu", 
                    (unsigned long long)domain_id);
            log_message("ERROR", err_buf);
        }
        if (domain_counters) {
            request_counter_t *counter = domain_counters;
            while (counter) {
                uint64_t route_hits = counter->cache_hits;
                uint64_t route_misses = counter->cache_misses;

                uint64_t route_byte_hit = 0;
                uint64_t route_byte_miss = 0;
                
                if (route_hits > 0) {
                    uint64_t total_cache_req = route_hits + route_misses;
                    if (total_cache_req > 0) {
                        route_byte_hit = (counter->bytes_out * route_hits) / total_cache_req;
                        route_byte_miss = counter->bytes_out - route_byte_hit;
                    }
                } else {
                    route_byte_miss = counter->bytes_out;
                }
                if (route_hits > 0 || route_misses > 0) {
                    if (dao_metrics_insert_route_cache(
                            flush_timestamp,
                            domain_id,
                            host,
                            counter->route,
                            route_hits,
                            route_misses,
                            route_byte_hit,
                            route_byte_miss) == 0) {
                        success_count++;
                    } else {
                        error_count++;
                        log_message("WARN", "metrics_flush: failed to insert route cache metrics");
                    }
                }
                
                counter = counter->next;
            }
        }
        if (domain_counters) {
            if (dao_metrics_insert_request_metrics_batch(domain_counters, flush_timestamp, domain_id, host) == 0) {
                success_count++;
            } else {
                error_count++;
                log_message("ERROR", "metrics_flush: failed to insert request metrics batch");
            }

            while (domain_counters) {
                request_counter_t *next = domain_counters->next;
                free(domain_counters);
                domain_counters = next;
            }
        }
    }

    if (counters) {
        while (counters) {
            request_counter_t *next = counters->next;
            free(counters);
            counters = next;
        }
    }

    uint64_t cache_hits = 0, cache_misses = 0, cache_evictions = 0, cache_bytes_used = 0;
    cache_get_metrics(&cache_hits, &cache_misses, &cache_evictions, &cache_bytes_used);
    
    uint64_t cached_bytes = 0, missed_bytes = 0;
    cache_get_egress_bytes(&cached_bytes, &missed_bytes);
    (void)cache_hits;
    (void)cache_misses;
    (void)cache_evictions;
    (void)cache_bytes_used;
    (void)cached_bytes;
    (void)missed_bytes;
    if (error_count > 0) {
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "metrics_flush: %d success, %d errors", success_count, error_count);
        log_message("WARN", log_buf);
    } else if (success_count > 0) {
        char log_buf[128];
        snprintf(log_buf, sizeof(log_buf), "metrics_flush: flushed %d operations successfully", success_count);
        log_message("INFO", log_buf);
    }

    if (error_count == 0) {
        request_tracker_reset();
    }
    
    return (error_count == 0) ? 0 : -1;
}


static unsigned __stdcall metrics_flush_thread_func(void *arg) {
    (void)arg;  // Unused
    
    InterlockedIncrement(&g_flush_running);
    
    log_message("INFO", "Metrics flush thread started");
    
    while (InterlockedCompareExchange(&g_flush_stop, 0, 0) == 0) {
        Sleep(60000);

        if (InterlockedCompareExchange(&g_flush_stop, 0, 0) != 0) {
            break;
        }

        time_t now = time(NULL);
        time_t current_minute = now - (now % 60);

        flush_metrics_to_db(current_minute);
    }
    
    InterlockedDecrement(&g_flush_running);
    
    log_message("INFO", "Metrics flush thread stopped");
    
    return 0;
}

int metrics_flush_thread_start(void) {
    if (InterlockedCompareExchange(&g_flush_running, 0, 0) != 0) {
        return 0;
    }

    InterlockedExchange(&g_flush_stop, 0);
    
    g_flush_thread = (HANDLE)_beginthreadex(
        NULL, 
        0,   
        metrics_flush_thread_func,
        NULL,
        0,   
        NULL             
    );
    
    if (g_flush_thread == NULL) {
        log_message("ERROR", "Failed to create metrics flush thread");
        return -1;
    }
    Sleep(100);
    
    if (InterlockedCompareExchange(&g_flush_running, 0, 0) == 0) {
        CloseHandle(g_flush_thread);
        g_flush_thread = NULL;
        log_message("ERROR", "Metrics flush thread failed to start");
        return -1;
    }
    
    return 0;
}

void metrics_flush_thread_stop(void) {
    if (InterlockedCompareExchange(&g_flush_running, 0, 0) == 0) {
        return;
    }

    InterlockedExchange(&g_flush_stop, 1);
 
    if (g_flush_thread) {
        DWORD wait_result = WaitForSingleObject(g_flush_thread, 5000);  // 5 second timeout
        if (wait_result == WAIT_TIMEOUT) {
            log_message("WARN", "Metrics flush thread did not stop within timeout");
            TerminateThread(g_flush_thread, 1);
        }
        CloseHandle(g_flush_thread);
        g_flush_thread = NULL;
    }

    time_t now = time(NULL);
    time_t current_minute = now - (now % 60);
    flush_metrics_to_db(current_minute);
}

int metrics_flush_thread_is_running(void) {
    return (InterlockedCompareExchange(&g_flush_running, 0, 0) != 0) ? 1 : 0;
}

