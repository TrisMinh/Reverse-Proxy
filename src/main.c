#include <stdio.h>
#include <stdlib.h>
#include "../include/config.h"
#include "../include/server.h"
#include "../include/logger.h"
#include "../include/threadpool.h"

int main() {
    create_log("../logs/proxy.log");

    Proxy_Config config;
    if (load_config("../config/proxy.conf",&config) != 0) {
        return EXIT_FAILURE;
    }

    int max_threads = 8; // Giới hạn số lượng thread
    init_thread_pool(max_threads);
    start_server(&config);


    close_log();
    
    return EXIT_SUCCESS;
}