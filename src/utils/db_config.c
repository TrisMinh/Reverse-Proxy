#include "../include/db_config.h"
#include "../include/logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static DBConfig global_db_conf;

static void set_default_db_config(DBConfig *conf) {
    memset(conf, 0, sizeof(*conf));
    snprintf(conf->host, sizeof(conf->host), "127.0.0.1");
    conf->port = 3306;
    snprintf(conf->username, sizeof(conf->username), "root");
    snprintf(conf->password, sizeof(conf->password), " ");
    snprintf(conf->database, sizeof(conf->database), "proxy_acl");
    snprintf(conf->charset, sizeof(conf->charset), "utf8mb4");
}

static void trim_line(char *line) {
    char *start = line;
    while (*start && isspace((unsigned char)*start))
        start++;
    if (start != line)
        memmove(line, start, strlen(start) + 1);

    char *end = line + strlen(line);
    while (end > line && isspace((unsigned char)*(end - 1)))
        end--;
    *end = '\0';
}

static int parse_db_line(const char *line) {
    if (sscanf(line, "host = %127s", global_db_conf.host) == 1) return 0;
    if (sscanf(line, "port = %d", &global_db_conf.port) == 1) return 0;
    if (sscanf(line, "username = %127s", global_db_conf.username) == 1) return 0;
    if (sscanf(line, "password = %127s", global_db_conf.password) == 1) return 0;
    if (sscanf(line, "database = %127s", global_db_conf.database) == 1) return 0;
    if (sscanf(line, "charset = %31s", global_db_conf.charset) == 1) return 0;

    return -1; 
}

int load_db_config(const char *filename) {
    set_default_db_config(&global_db_conf);

    FILE *file = fopen(filename, "r");
    if (!file) {
        int err = errno;
        printf("[DBCONFIG] Cannot open %s (%s), using defaults\n", filename, strerror(err));
        log_message("ERROR", "Cannot open DB config file, using defaults");
        return -1;
    }

    char line[256];
    int has_error = 0;

    while (fgets(line, sizeof(line), file)) {
        trim_line(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        char *comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
            trim_line(line);
            if (line[0] == '\0') continue;
        }

        if (parse_db_line(line) != 0) {
            has_error = 1;
            log_message("WARN", "Unknown DB config entry encountered");
        }
    }

    fclose(file);

    if (has_error)
        log_message("WARN", "DB config loaded with warnings");
    else
        log_message("INFO", "DB config loaded successfully");

    return 0;
}

DBConfig *get_db_config(void) {
    return &global_db_conf;
}
