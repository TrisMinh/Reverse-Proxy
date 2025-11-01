#include "dao_acl.h"
#include "dbhelper.h"
#include <stdio.h>

int dao_acl_add(const char *ip) {
    char query[256];
    snprintf(query, sizeof(query),
             "INSERT IGNORE INTO blacklist (ip, created_at) VALUES ('%s', NOW())", ip);
    return db_execute(query);
}

int dao_acl_exists(const char *ip) {
    char query[256];
    snprintf(query, sizeof(query),
             "SELECT 1 FROM blacklist WHERE ip='%s' LIMIT 1", ip);

    MYSQL_RES *res = db_query(query);
    if (!res) return 0;

    int exists = mysql_num_rows(res) > 0;
    mysql_free_result(res);
    return exists;
}

int dao_acl_remove(const char *ip) {
    char query[256];
    snprintf(query, sizeof(query),
             "DELETE FROM blacklist WHERE ip='%s'", ip);
    return db_execute(query);
}

int dao_acl_load_all(ipset_t *s) {
    MYSQL_RES *res = db_query("SELECT ip FROM blacklist");
    if (!res) return -1;

    MYSQL_ROW row;
    int count = 0;
    ipset_init(s);

    while ((row = mysql_fetch_row(res))) {
        if (row[0]) {
            ipset_add(s, row[0]);
            count++;
        }
    }
    mysql_free_result(res);
    printf("[DAO] Loaded %d IPs from DB\n", count);
    return count;
}
