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
#include "../include/captcha_filter.h"  // Disabled: missing curl library
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
        Sleep(30000);
        acl_reload();
        load_proxy_routes();
        printf("[ACL] Reloaded from database.");
    }
}

unsigned __stdcall https_thread(void *arg) {
    start_https_server();
    return 0;
}

int main(){
    char exe_path[MAX_PATH];
    int is_in_build_dir = 0;
    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) > 0) {
        char *last_slash = strrchr(exe_path, '\\');
        if (last_slash) {
            *last_slash = '\0';
            // Check if we're in build directory
            if (strstr(exe_path, "build") != NULL) {
                is_in_build_dir = 1;
                SetCurrentDirectoryA(exe_path);
                SetCurrentDirectoryA("..");  // Go to project root
            } else {
                SetCurrentDirectoryA(exe_path);
            }
        }
    }
    
    // Use relative paths based on whether we're in project root or build directory
    const char *config_prefix = is_in_build_dir ? "config" : "../config";
    const char *logs_prefix = is_in_build_dir ? "logs" : "../logs";
    
    char log_path[MAX_PATH];
    snprintf(log_path, sizeof(log_path), "%s/proxy.log", logs_prefix);
    create_log(log_path);
    
    load_proxy_routes();

    char proxy_conf_path[MAX_PATH];
    snprintf(proxy_conf_path, sizeof(proxy_conf_path), "%s/proxy.conf", config_prefix);
    int config_rs = load_config(proxy_conf_path);

    if (config_rs != 0) {
        fprintf(stderr, "Failed to load config from: %s\n", proxy_conf_path);
        fprintf(stderr, "Press any key to exit...\n");
        system("pause >nul");
        return 1;
    }

    char db_conf_path[MAX_PATH];
    snprintf(db_conf_path, sizeof(db_conf_path), "%s/db.conf", config_prefix);
    int db_config_rs = load_db_config(db_conf_path);
    if (db_config_rs != 0) {
        fprintf(stderr, "Failed to load db config from: %s\n", db_conf_path);
        fprintf(stderr, "Press any key to exit...\n");
        system("pause >nul");
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
    // set_captcha_config(cfg->captcha_center_url, cfg->captcha_secret_key, cfg->recaptcha_secret_key, cfg->captcha_callback_path, cfg->captcha_state_ttl_sec, cfg->captcha_pass_ttl_sec);  // Disabled: captcha_filter removed

    global_ssl_ctx = init_ssl_ctx();
    if (!global_ssl_ctx) {
        fprintf(stderr, "Failed to initialize OpenSSL client context\n");
        fprintf(stderr, "Press any key to exit...\n");
        system("pause >nul");
        return 1;
    }

    // OpenSSL server-side context (frontend HTTPS) - Optional
    global_ssl_server_ctx = init_ssl_server_ctx();
    if (!global_ssl_server_ctx) {
        fprintf(stderr, "WARNING: Failed to initialize SSL server context\n");
        fprintf(stderr, "HTTPS server will not be available. HTTP server will still run.\n");
        fprintf(stderr, "To enable HTTPS, create certificate files:\n");
        fprintf(stderr, "  - %s/default.crt\n", cfg->cert_dir);
        fprintf(stderr, "  - %s/default.key\n", cfg->cert_dir);
        log_message("WARN", "SSL server context initialization failed - HTTPS disabled");
    } else {
        log_message("INFO", "SSL server context initialized successfully");
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
            printf("Failed to initialize cache\n");
            log_message("ERROR", "Failed to initialize cache");
        } else {
            log_message("INFO", "Cache initialized successfully");
        }
    } else {
        log_message("INFO", "Cache disabled in config");
    }
    
    // Initialize request tracker
    if (request_tracker_init() != 0) {
        printf("Failed to initialize request tracker\n");
        log_message("ERROR", "Failed to initialize request tracker");
    } else {
        log_message("INFO", "Request tracker initialized successfully");
    }
    
    // Start metrics flush thread
    if (metrics_flush_thread_start() != 0) {
        printf("Failed to start metrics flush thread\n");
        log_message("ERROR", "Failed to start metrics flush thread");
    } else {
        log_message("INFO", "Metrics flush thread started");
    }
    
    initThreadPool(&pool,MAX_THREADS);
    // Thread reload ACL mỗi ... sec
    _beginthread(acl_reloader_thread, 0, NULL);
    // Only start HTTPS server if SSL context is available
    if (global_ssl_server_ctx) {
    _beginthreadex(NULL, 0, https_thread, NULL, 0, NULL);
    }
    start_server();
    
    // If we reach here, start_server() returned (server failed to start or exited)
    fprintf(stderr, "\n[INFO] Server stopped. Cleaning up...\n");
    
    shutdownThreadPool(&pool);

    free_ssl_cert_cache();
    cleanup_ssl_ctx(global_ssl_server_ctx);
    cleanup_ssl_ctx(global_ssl_ctx);
    // Shutdown cache
    if (cfg->cache_enabled) {
        cache_shutdown();
    }
    
    // Stop metrics flush thread
    metrics_flush_thread_stop();
    
    // Shutdown request tracker
    request_tracker_shutdown();
    
    // Close database connection
    db_close();
    
    rate_limit_shutdown();
    shutdown_filter_chain();
    close_log();
    return 0;
}
