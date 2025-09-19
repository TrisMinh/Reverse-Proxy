#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    char listen_host[16]; // chon 16 vi 255.255.255.255 max la 15 them \n la 16
    int listen_port;
    char backend_host[16];
    int backend_port;
    int max_connection;
    int timeout;
    int keep_alive;
    int connection_retries;
    char log_file[256];
    char log_level[16];
} Proxy_Config;

int load_config();
Proxy_Config *get_config();

#endif