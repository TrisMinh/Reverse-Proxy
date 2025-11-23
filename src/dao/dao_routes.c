#include "../include/dao_routes.h"
#include "../include/dbhelper.h"
#include "../include/proxy_routes.h"
#include <mysql.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int dao_routes_load_all_into(ProxyRoute *out, int max_out) {
    if (!out || max_out <= 0) return 0;

    const char *q =
    "SELECT d.domain, o.origin_ip AS backend_host, o.backend_port FROM domains d LEFT JOIN domain_origins o ON o.domain_id = d.id WHERE d.status = 1 ORDER BY d.id, o.id";

    MYSQL_RES *res = db_query(q);
    if (!res) return 0;

    MYSQL_ROW row;
    int n = 0;

    while ((row = mysql_fetch_row(res)) && n < max_out) {
        const char *c_domain = row[0];
        const char *c_host   = row[1];
        const char *c_port   = row[2];

        if (!c_domain || !c_domain[0]) continue;

        ProxyRoute *r = &out[n++];

        snprintf(r->domain, sizeof(r->domain), "%s", c_domain);

        if (c_host && c_host[0]) {
            snprintf(r->backend_host, sizeof(r->backend_host), "%s", c_host);
        } else {
            r->backend_host[0] = '\0';
        }

        if (c_port && c_port[0]) {
            r->backend_port   = atoi(c_port);
        } else {
            r->backend_port   = 0;
        }

        r->is_https = -1;
    }

    mysql_free_result(res);
    return n;
}
