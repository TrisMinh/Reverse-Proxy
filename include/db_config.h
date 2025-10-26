#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#define MAX_DB_FIELD 128

typedef struct {
    char host[MAX_DB_FIELD];
    int  port;
    char username[MAX_DB_FIELD];
    char password[MAX_DB_FIELD];
    char database[MAX_DB_FIELD];
    char charset[32];
} DBConfig;

int load_db_config(const char *filename);
DBConfig *get_db_config(void);

#endif
