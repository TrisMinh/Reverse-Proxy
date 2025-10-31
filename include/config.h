#ifndef CONFIG_H
#define CONFIG_H

#define MAX_HOST_LEN 64

typedef struct {
    char listen_host[MAX_HOST_LEN];
    int listen_port;
    char backend_host[MAX_HOST_LEN];
    int backend_port;
    int max_connection;
    int timeout;
    int keep_alive;
    int connection_retries;
    char log_file[MAX_HOST_LEN];
    char log_level[MAX_HOST_LEN];
    char acme_webroot[260];
    char cert_dir[512];
    long long header_limit;
    long long body_limit;
    char captcha_center_url[512];
    char captcha_secret_key[512];
    char recaptcha_secret_key[512];
    char captcha_callback_path[512];
    int captcha_state_ttl_sec;
    int captcha_pass_ttl_sec;
} Proxy_Config;

int load_config(const char* filename);
Proxy_Config* get_config();

#endif
