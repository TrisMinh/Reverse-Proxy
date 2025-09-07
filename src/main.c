#include <stdio.h>
#include <stdlib.h>
#include "../include/config.h"
#include "../include/server.h"
#include "../include/logger.h"

int main() {
    Proxy_Config config;
    if (load_config("config/proxy.conf",&config) != 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}