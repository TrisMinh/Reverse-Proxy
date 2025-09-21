#include <stdio.h>
#include <stdlib.h>
#include "../include/config.h"
#include "../include/server.h"
#include "../include/logger.h"
#include "../include/threadpool.h"
#include "../include/ssl_utils.h"
#include "../include/proxy_routes.h"
#include <windows.h>

SSL_CTX *global_ssl_ctx = NULL;

int main() {
    create_log("../logs/proxy.log");
    load_proxy_routes("../config/proxy_routes.conf");

    if (load_config() != 0) {
        return EXIT_FAILURE;
    }

    // Khởi tạo OpenSSL
    global_ssl_ctx = init_ssl_ctx();
    if (!global_ssl_ctx) {
        printf("Failed to initialize OpenSSL\n");
        return EXIT_FAILURE;
    }

    int max_threads = 8; // Giới hạn số lượng thread
    init_thread_pool(max_threads);
    start_server();


    close_log();
    cleanup_ssl_ctx(global_ssl_ctx);
    
    return EXIT_SUCCESS;
}