#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/config.h"
#include "../include/logger.h"

int load_config(const char *filename, Proxy_Config *config) {
    FILE *file = fopen(filename,"r");
    if (file == NULL) {
        printf("Cannot open config file\n");
        return -1;
    }

    char line[256];
    int has_error = 0;  // 0 = không lỗi, 1 = có lỗi

    while(fgets(line,sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        // Bỏ comment trong dòng
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        
        if (sscanf(line, "listen_host = %15s", config->listen_host) == 1) continue;
        if (sscanf(line, "listen_port = %d", &config->listen_port) == 1) continue;
        if (sscanf(line, "backend_host = %15s", config->backend_host) == 1) continue;
        if (sscanf(line, "backend_port = %d", &config->backend_port) == 1) continue;
        if (sscanf(line, "max_connection = %d", &config->max_connection) == 1) continue;
        if (sscanf(line, "timeout = %d", &config->timeout) == 1) continue;
        if (sscanf(line, "keep_alive = %d", &config->keep_alive) == 1) continue;
        if (sscanf(line, "connection_retries = %d", &config->connection_retries) == 1) continue;
        if (sscanf(line, "log_file = %255s", config->log_file) == 1) continue;
        if (sscanf(line, "log_level = %15s", config->log_level) == 1) continue;
        
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