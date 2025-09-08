#include <stdio.h>
#include <stdlib.h>
#include "../include/config.h"
#include "../include/server.h"
#include "../include/logger.h"

int main() {
    create_log("../logs/proxy.log");

    Proxy_Config config;
    if (load_config("../config/proxy.conf",&config) != 0) {
        return EXIT_FAILURE;
    }

    start_server(&config);


    close_log();
    
    return EXIT_SUCCESS;
}