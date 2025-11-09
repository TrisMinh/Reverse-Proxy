#include "dbhelper.h"
#include "../include/logger.h"
#include <stdio.h>

static MYSQL *g_conn = NULL;

int db_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port) {
    g_conn = mysql_init(NULL);
    if (!g_conn) {
        printf("[MYSQL] init failed\n");
        return -1;
    }

    if (!mysql_real_connect(g_conn, host, user, pass, db, port, NULL, 0)) {
        printf("[MYSQL] connect failed: %s\n", mysql_error(g_conn));
        return -1;
    }

    printf("[MYSQL] Connected to %s:%u\n", host, port);
    return 0;
}

void db_close() {
    if (g_conn) {
        mysql_close(g_conn);
        g_conn = NULL;
    }
}

int db_execute(const char *query) {
    if (!g_conn || !query) return -1;

    if (mysql_query(g_conn, query) == 0)
        return 0;

    const char *error = mysql_error(g_conn);
    unsigned int mysql_err = mysql_errno(g_conn);
    
    // Log to both stdout and logger
    printf("[MYSQL] Query error [%u]: %s\n", mysql_err, error);
    
    // Log query (truncate if too long)
    char query_log[512];
    size_t query_len = strlen(query);
    if (query_len > 500) {
        strncpy(query_log, query, 500);
        query_log[500] = '\0';
        strcat(query_log, "...");
    } else {
        strcpy(query_log, query);
    }
    
    char log_buf[1024];
    snprintf(log_buf, sizeof(log_buf), "[MYSQL] Query error [%u]: %s | Query: %s", mysql_err, error, query_log);
    log_message("ERROR", log_buf);
    
    return -1;
}

MYSQL_RES* db_query(const char *query) {
    if (!g_conn || !query) return NULL;

    if (mysql_query(g_conn, query)) {
        const char *error = mysql_error(g_conn);
        unsigned int mysql_err = mysql_errno(g_conn);
        
        printf("[MYSQL] Query error [%u]: %s\n", mysql_err, error);
        
        char query_log[512];
        size_t query_len = strlen(query);
        if (query_len > 500) {
            strncpy(query_log, query, 500);
            query_log[500] = '\0';
            strcat(query_log, "...");
        } else {
            strcpy(query_log, query);
        }
        
        char log_buf[1024];
        snprintf(log_buf, sizeof(log_buf), "[MYSQL] Query error [%u]: %s | Query: %s", mysql_err, error, query_log);
        log_message("ERROR", log_buf);
        
        return NULL;
    }
    return mysql_store_result(g_conn);
}
