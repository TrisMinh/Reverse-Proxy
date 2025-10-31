#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../include/config.h"
#include "../include/logger.h"

static Proxy_Config global_config;

static void set_default_config(Proxy_Config *config) {
    memset(config, 0, sizeof(*config));

    snprintf(config->listen_host, MAX_HOST_LEN, "0.0.0.0");
    config->listen_port = 4000;

    snprintf(config->backend_host, MAX_HOST_LEN, "127.0.0.1");
    config->backend_port = 3000;

    config->max_connection = 200;
    config->timeout = 30;
    config->keep_alive = 1;
    config->connection_retries = 3;

    config->header_limit = 131072;
    config->body_limit   = 104857600;

    snprintf(config->log_file, MAX_HOST_LEN, "logs/proxy.log");
    snprintf(config->log_level, MAX_HOST_LEN, "info");
}

static int parse_line(const char *line) {
    if (sscanf(line, "listen_host = %63s", global_config.listen_host) == 1) return 0;
    if (sscanf(line, "listen_port = %d", &global_config.listen_port) == 1) return 0;
    if (sscanf(line, "backend_host = %63s", global_config.backend_host) == 1) return 0;
    if (sscanf(line, "backend_port = %d", &global_config.backend_port) == 1) return 0;
    if (sscanf(line, "max_connection = %d", &global_config.max_connection) == 1) return 0;
    if (sscanf(line, "timeout = %d", &global_config.timeout) == 1) return 0;
    if (sscanf(line, "keep_alive = %d", &global_config.keep_alive) == 1) return 0;
    if (sscanf(line, "connection_retries = %d", &global_config.connection_retries) == 1) return 0;
    if (sscanf(line, "log_file = %63s", global_config.log_file) == 1) return 0;
    if (sscanf(line, "log_level = %63s", global_config.log_level) == 1) return 0;
    if (sscanf(line, "acme_webroot = %63s", global_config.acme_webroot) == 1) return 0;
    if (sscanf(line, "cert_dir = %63s", global_config.cert_dir) == 1) return 0;
    if (sscanf(line, "header_limit = %lld", &global_config.header_limit) == 1) return 0;
    if (sscanf(line, "body_limit = %lld",   &global_config.body_limit)   == 1) return 0;
    if (sscanf(line, "captcha_center_url = \"%255[^\"]\"", global_config.captcha_center_url) == 1) return 0;
    if (sscanf(line, "captcha_secret_key = \"%255[^\"]\"", global_config.captcha_secret_key) == 1) return 0;
    if (sscanf(line, "recaptcha_secret_key = \"%255[^\"]\"", global_config.recaptcha_secret_key) == 1) return 0;
    if (sscanf(line, "captcha_callback_path = \"%255[^\"]\"", global_config.captcha_callback_path) == 1) return 0;
    if (sscanf(line, "captcha_state_ttl_sec = %d", &global_config.captcha_state_ttl_sec) == 1) return 0;
    if (sscanf(line, "captcha_pass_ttl_sec = %d", &global_config.captcha_pass_ttl_sec) == 1) return 0;

    return -1;
}

static void trim_line(char *line) {
    char *start = line;
    while (*start && isspace((unsigned char)*start)) start++;

    if (start != line) memmove(line, start, strlen(start) + 1);

    char *end = line + strlen(line);
    while (end > line && isspace((unsigned char)*(end - 1))) end--;
    *end = '\0';
}

int load_config(const char *filename) {
    const char *config_file = filename;
    set_default_config(&global_config);

    FILE *file = fopen(config_file, "r");
    if (file == NULL) {
        int err = errno;
        printf("Cannot open config file (%s), using defaults\n", strerror(err));
        log_message("ERROR", "Cannot open config file, using defaults");
        return -1;
    }

    char line[256];
    int has_error = 0;

    while (fgets(line, sizeof(line), file)) {
        trim_line(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
            trim_line(line);
            if (line[0] == '\0') continue;
        }

        if (parse_line(line) != 0) {
            has_error = 1;
            log_message("WARN", "Unknown config entry encountered");
        }
    }

    fclose(file);

    if (has_error) {
        log_message("WARN", "Config loaded with warnings");
        return 0;
    }

    log_message("INFO", "Config loaded successfully");
    return 0;
}

Proxy_Config *get_config(void) {
    return &global_config;
}
