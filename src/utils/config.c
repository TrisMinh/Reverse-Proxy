#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/config.h"
#include "../include/logger.h"

static Proxy_Config global_config;

// Function to initialize and load the global configuration
int load_config() {
    const char *config_file = "../config/proxy.conf";
    FILE *file = fopen(config_file, "r");
    if (file == NULL) {
        perror("Cannot open config file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    int has_error = 0;  // 0 = không lỗi, 1 = có lỗi

    while(fgets(line,sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        // Bỏ comment trong dòng
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        
        if (sscanf(line, "listen_host = %15s", global_config.listen_host) == 1) continue;
        if (sscanf(line, "listen_port = %d", &global_config.listen_port) == 1) continue;
        if (sscanf(line, "backend_host = %15s", global_config.backend_host) == 1) continue;
        if (sscanf(line, "backend_port = %d", &global_config.backend_port) == 1) continue;
        if (sscanf(line, "max_connection = %d", &global_config.max_connection) == 1) continue;
        if (sscanf(line, "timeout = %d", &global_config.timeout) == 1) continue;
        if (sscanf(line, "keep_alive = %d", &global_config.keep_alive) == 1) continue;
        if (sscanf(line, "connection_retries = %d", &global_config.connection_retries) == 1) continue;
        if (sscanf(line, "log_file = %255s", global_config.log_file) == 1) continue;
        if (sscanf(line, "log_level = %15s", global_config.log_level) == 1) continue;
        
        // Nếu đến đây nghĩa là dòng không match với field nào
        has_error = 1;
    }

    fclose(file);

    if (has_error) {
        printf("Load config failed!\n");
        log_message("ERROR", "Load config failed!");
        return -1;
    }

    printf("Load config succeeded!\n");
    log_message("INFO", "Load config succeeded!");
    return 0;
}

Proxy_Config *get_config() {
    return &global_config;
}