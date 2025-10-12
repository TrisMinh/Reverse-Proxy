#include "config.h"
#include "server.h"
#include "logger.h"
#include "threadpool.h"
#include "../include/ssl_utils.h"
#include "../include/filter_chain.h"
#include "../include/proxy_routes.h"
#include "../include/rate_limit.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

SSL_CTX *global_ssl_ctx = NULL;
SSL_CTX *global_ssl_server_ctx = NULL;

#define MAX_THREADS 32

ThreadPool pool;

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
    rate_limit_init();
    register_filter(rate_limit_filter);

    initThreadPool(&pool,MAX_THREADS);
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
