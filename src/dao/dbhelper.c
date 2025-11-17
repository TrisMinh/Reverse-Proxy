#include "dbhelper.h"
#include <stdio.h>
#include <windows.h>

static MYSQL *g_conn = NULL;
static CRITICAL_SECTION g_db_lock;
static int g_lock_initialized = 0;

static void ensure_lock() {
    if (!g_lock_initialized) {
        InitializeCriticalSection(&g_db_lock);
        g_lock_initialized = 1;
    }
}

int db_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port) {
    ensure_lock();
    EnterCriticalSection(&g_db_lock);
    
    g_conn = mysql_init(NULL);
    if (!g_conn) {
        printf("[MYSQL] init failed\n");
        LeaveCriticalSection(&g_db_lock);
        return -1;
    }

    if (!mysql_real_connect(g_conn, host, user, pass, db, port, NULL, 0)) {
        printf("[MYSQL] connect failed: %s\n", mysql_error(g_conn));
        mysql_close(g_conn);
        g_conn = NULL;
        LeaveCriticalSection(&g_db_lock);
        return -1;
    }

    printf("[MYSQL] Connected to %s:%u\n", host, port);
    LeaveCriticalSection(&g_db_lock);
    return 0;
}

void db_close() {
    ensure_lock();
    EnterCriticalSection(&g_db_lock);
    
    if (g_conn) {
        mysql_close(g_conn);
        g_conn = NULL;
    }
    
    LeaveCriticalSection(&g_db_lock);
    
    if (g_lock_initialized) {
        DeleteCriticalSection(&g_db_lock);
        g_lock_initialized = 0;
    }
}

int db_execute(const char *query) {
    if (!g_conn || !query) return -1;

    ensure_lock();
    EnterCriticalSection(&g_db_lock);
    
    int result = -1;
    if (mysql_query(g_conn, query) == 0) {
        result = 0;
    } else {
        printf("[MYSQL] Query error: %s\n", mysql_error(g_conn));
        result = -1;
    }
    
    LeaveCriticalSection(&g_db_lock);
    return result;
}

MYSQL_RES* db_query(const char *query) {
    if (!g_conn || !query) return NULL;

    ensure_lock();
    EnterCriticalSection(&g_db_lock);
    
    MYSQL_RES *result = NULL;
    if (mysql_query(g_conn, query) == 0) {
        result = mysql_store_result(g_conn);
    } else {
        printf("[MYSQL] Query error: %s\n", mysql_error(g_conn));
        result = NULL;
    }
    
    LeaveCriticalSection(&g_db_lock);
    return result;
}
