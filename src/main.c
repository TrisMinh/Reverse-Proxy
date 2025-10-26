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
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

SSL_CTX *global_ssl_ctx = NULL;
SSL_CTX *global_ssl_server_ctx = NULL;

#define MAX_THREADS 32

ThreadPool pool;

void __cdecl acl_reloader_thread(void *arg) {
    while (1) {
        Sleep(10000);
        acl_reload();
        printf("[ACL] Reloaded from database.");
    }
}


unsigned __stdcall https_thread(void *arg) {
    start_https_server();
    return 0;
}

int main(){
    create_log("../logs/proxy.log");
    load_proxy_routes("../config/proxy_routes.conf");


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

    const Proxy_Config *cfg = get_config();
    frg_set_header_limit(cfg->header_limit);
    frg_set_body_limit(cfg->body_limit);

    // OpenSSL client-side context (backend HTTPS)
    global_ssl_ctx = init_ssl_ctx();
    if (!global_ssl_ctx) {
        printf("Failed to initialize OpenSSL client context\n");
        return 1;
    }

    // OpenSSL server-side context (frontend HTTPS)
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
    
    initThreadPool(&pool,MAX_THREADS);
    // Thread reload ACL mỗi 30 giây
    _beginthread(acl_reloader_thread, 0, NULL);
    _beginthreadex(NULL, 0, https_thread, NULL, 0, NULL);
    start_server();
    shutdownThreadPool(&pool);

    free_ssl_cert_cache();
    cleanup_ssl_ctx(global_ssl_server_ctx);
    cleanup_ssl_ctx(global_ssl_ctx);
    rate_limit_shutdown();
    shutdown_filter_chain();
    close_log();
    return 0;
}
