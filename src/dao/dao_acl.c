#include "dao_acl.h"
#include "dbhelper.h"
#include <stdio.h>

int dao_acl_add(const char *ip, const char *domain) {
    char query[512];
    const char *d = (domain && domain[0]) ? domain : "*";
    snprintf(query, sizeof(query),
             "INSERT IGNORE INTO blacklist (ip, domain, created_at) VALUES ('%s', '%s', NOW())", ip, d);
    return db_execute(query);
}

int dao_acl_exists(const char *ip, const char *domain) {
    char query[512];
    const char *d = (domain && domain[0]) ? domain : "*";
    snprintf(query, sizeof(query),
             "SELECT 1 FROM blacklist WHERE ip='%s' AND domain='%s' LIMIT 1", ip, d);

    MYSQL_RES *res = db_query(query);
    if (!res) return 0;

    int exists = mysql_num_rows(res) > 0;
    mysql_free_result(res);
    return exists;
}

int dao_acl_remove(const char *ip, const char *domain) {
    char query[512];
    const char *d = (domain && domain[0]) ? domain : "*";
    snprintf(query, sizeof(query),
             "DELETE FROM blacklist WHERE ip='%s' AND domain='%s'", ip, d);
    return db_execute(query);
}

int dao_acl_load_all(ipset_t *s) {
    MYSQL_RES *res = db_query("SELECT ip, domain FROM blacklist");
    if (!res) return -1;

    MYSQL_ROW row;
    int count = 0;
    ipset_init(s);

    while ((row = mysql_fetch_row(res))) {
        if (row[0] && row[1]) {
            ipset_add(s, row[0], row[1]);
            count++;
        }
    }
    mysql_free_result(res);
    printf("[DAO] Loaded %d IP-domain pairs from DB\n", count);
    return count;
}
