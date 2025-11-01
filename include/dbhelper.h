#ifndef DBHELPER_H
#define DBHELPER_H

#include <mysql.h>

int db_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port);
void db_close();
int db_execute(const char *query);
MYSQL_RES* db_query(const char *query);

#endif
