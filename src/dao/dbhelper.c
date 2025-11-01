#include "dbhelper.h"
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

    printf("[MYSQL] Query error: %s\n", mysql_error(g_conn));
    return -1;
}

MYSQL_RES* db_query(const char *query) {
    if (!g_conn || !query) return NULL;

    if (mysql_query(g_conn, query)) {
        printf("[MYSQL] Query error: %s\n", mysql_error(g_conn));
        return NULL;
    }
    return mysql_store_result(g_conn);
}
