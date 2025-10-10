#include "config.h"
#include "server.h"
#include "logger.h"
#include "threadpool.h"
#include "../include/ssl_utils.h"
#include "../include/proxy_routes.h"
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
    create_log("proxy.log");
    load_proxy_routes("../config/proxy_routes.conf");


    Proxy_Config config;
    if(load_config()!=0){
        printf("Load config failed, fallback default\n");
        snprintf(config.listen_host,sizeof(config.listen_host),"0.0.0.0");
        config.listen_port=4445;
        snprintf(config.backend_host,sizeof(config.backend_host),"example.com");
        config.backend_port=80;
        config.max_connection=100;
        config.timeout=30;
        config.keep_alive=1;
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

    initThreadPool(&pool,MAX_THREADS);
    _beginthreadex(NULL, 0, https_thread, NULL, 0, NULL);
    start_server();
    shutdownThreadPool(&pool);

    free_ssl_cert_cache();
    cleanup_ssl_ctx(global_ssl_server_ctx);
    cleanup_ssl_ctx(global_ssl_ctx);
    close_log();
    return 0;
}
