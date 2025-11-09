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
    conf->password[0] = '\0'; 
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
    char key[64], value[256] = "";

    char *equal_pos = strchr(line, '=');
    if (!equal_pos) {
        return -1;
    }
 
    int key_len = equal_pos - line;
    if (key_len >= sizeof(key)) key_len = sizeof(key) - 1;
    strncpy(key, line, key_len);
    key[key_len] = '\0';

    for (int i = strlen(key) - 1; i >= 0 && isspace((unsigned char)key[i]); i--) {
        key[i] = '\0';
    }

    const char *value_start = equal_pos + 1;
    while (*value_start && isspace((unsigned char)*value_start)) {
        value_start++;
    }

    strncpy(value, value_start, sizeof(value) - 1);
    value[sizeof(value) - 1] = '\0';
    
    // Trim value
    int val_len = strlen(value);
    while (val_len > 0 && isspace((unsigned char)value[val_len - 1])) {
        val_len--;
        value[val_len] = '\0';
    }

    if (strcmp(key, "password") == 0) {
        val_len = strlen(value);
        if (val_len >= 2 && value[0] == '"' && value[val_len-1] == '"') {
            value[val_len-1] = '\0';
            strncpy(global_db_conf.password, value + 1, sizeof(global_db_conf.password) - 1);
            global_db_conf.password[sizeof(global_db_conf.password) - 1] = '\0';
        } else {
            strncpy(global_db_conf.password, value, sizeof(global_db_conf.password) - 1);
            global_db_conf.password[sizeof(global_db_conf.password) - 1] = '\0';
        }
        return 0;
    }
    if (strcmp(key, "host") == 0) {
        strncpy(global_db_conf.host, value, sizeof(global_db_conf.host) - 1);
        global_db_conf.host[sizeof(global_db_conf.host) - 1] = '\0';
        return 0;
    }
    if (strcmp(key, "port") == 0) {
        global_db_conf.port = atoi(value);
        return 0;
    }
    if (strcmp(key, "username") == 0) {
        strncpy(global_db_conf.username, value, sizeof(global_db_conf.username) - 1);
        global_db_conf.username[sizeof(global_db_conf.username) - 1] = '\0';
        return 0;
    }
    if (strcmp(key, "database") == 0) {
        strncpy(global_db_conf.database, value, sizeof(global_db_conf.database) - 1);
        global_db_conf.database[sizeof(global_db_conf.database) - 1] = '\0';
        return 0;
    }
    if (strcmp(key, "charset") == 0) {
        strncpy(global_db_conf.charset, value, sizeof(global_db_conf.charset) - 1);
        global_db_conf.charset[sizeof(global_db_conf.charset) - 1] = '\0';
        return 0;
    }

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
