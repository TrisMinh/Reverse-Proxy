#include "config.h"
#include "db_config.h"
#include "server.h"
#include "logger.h"
#include "threadpool.h"
#include "../include/ssl_utils.h"
#include "../include/filter_chain.h"
#include "../include/proxy_routes.h"
#include "../include/rate_limit.h"
#include "../include/acl_filter.h"
#include "../include/waf_sql.h"
#include "../include/filter_request_guard.h"
#include "../include/captcha_filter.h"
#include "../include/cache.h"
#include "../include/request_metrics.h"
#include "../include/metrics_flush.h"
#include "../include/dbhelper.h"
#include "../include/db_config.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SSL_CTX *global_ssl_ctx = NULL;
SSL_CTX *global_ssl_server_ctx = NULL;

#define MAX_THREADS 32

ThreadPool pool;

void __cdecl acl_reloader_thread(void *arg) {
    while (1) {
        Sleep(10000);
        acl_reload();
        load_proxy_routes();
        // printf("[ACL] Reloaded from database.");
    }
}

unsigned __stdcall https_thread(void *arg) {
    start_https_server();
    return 0;
}

int main(){
    create_log("../logs/proxy.log");
    
    int config_rs = load_config("../config/proxy.conf");
    if (config_rs != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    int db_config_rs = load_db_config("../config/db.conf");
    if (db_config_rs != 0) {
        fprintf(stderr, "Failed to load db config\n");
        return 1;
    }

    // Connect to database for metrics
    DBConfig *db_conf = get_db_config();
    if (db_connect(db_conf->host, db_conf->username, db_conf->password, 
                   db_conf->database, db_conf->port) != 0) {
        fprintf(stderr, "Failed to connect to database\n");
        log_message("WARN", "Database connection failed, metrics flushing may not work");
    } else {
        log_message("INFO", "Database connected successfully");
    }

    const Proxy_Config *cfg = get_config();
    frg_set_header_limit(cfg->header_limit);
    frg_set_body_limit(cfg->body_limit);
    set_captcha_config(cfg->captcha_center_url, cfg->captcha_secret_key, cfg->recaptcha_secret_key, cfg->captcha_callback_path, cfg->captcha_state_ttl_sec, cfg->captcha_pass_ttl_sec);

    global_ssl_ctx = init_ssl_ctx();
    if (!global_ssl_ctx) {
        printf("Failed to initialize OpenSSL client context\n");
        return 1;
    }

    global_ssl_server_ctx = init_ssl_server_ctx();
    if (!global_ssl_server_ctx) {
        printf("Failed to initialize SSL server context\n");
        return 1;
    }

    // Khởi tạo filter chain (danh sách filter trống ban đầu)
    init_filter_chain();

    register_filter(frg_chain_validate);

    acl_init();
    register_filter(acl_filter);
    
    rate_limit_init();
    register_filter(rate_limit_filter);

    register_filter(waf_sql_filter);

    register_filter(captcha_filter);
    
    // Initialize cache
    if (cfg->cache_enabled) {
        if (cache_init(cfg->cache_max_bytes, cfg->cache_default_ttl_sec, cfg->cache_second_hit_window) != 0) {
            fprintf(stderr, "Failed to initialize cache\n");
            log_message("ERROR", "Cache initialization failed");
        } else {
            log_message("INFO", "Cache initialized successfully");
        }
    }

    // Initialize request tracker
    if (request_tracker_init() != 0) {
        fprintf(stderr, "Failed to initialize request tracker\n");
        log_message("ERROR", "Request tracker initialization failed");
    }

    // Start metrics flush thread
    if (metrics_flush_thread_start() != 0) {
        fprintf(stderr, "Failed to start metrics flush thread\n");
        log_message("ERROR", "Metrics flush thread failed to start");
    }
    
    load_proxy_routes();
    initThreadPool(&pool,MAX_THREADS);
    // Thread reload ACL mỗi ... sec
    _beginthread(acl_reloader_thread, 0, NULL);
    _beginthreadex(NULL, 0, https_thread, NULL, 0, NULL);
    start_server();
    shutdownThreadPool(&pool);

    // Stop metrics flush thread
    metrics_flush_thread_stop();
    
    // Shutdown request tracker
    request_tracker_shutdown();
    
    // Shutdown cache
    if (cfg->cache_enabled) {
        cache_shutdown();
    }

    free_ssl_cert_cache();
    cleanup_ssl_ctx(global_ssl_server_ctx);
    cleanup_ssl_ctx(global_ssl_ctx);
    rate_limit_shutdown();
    shutdown_filter_chain();
    db_close();
    close_log();
    return 0;
}
