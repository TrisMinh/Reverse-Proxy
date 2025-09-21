#include "config.h"
#include "server.h"
#include "logger.h"
#include "threadpool.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_THREADS 8

ThreadPool pool;

int main(){
    create_log("proxy.log");

    Proxy_Config config;
    if(load_config()!=0){
        printf("Load config failed, fallback default\n");
        snprintf(config.listen_host,sizeof(config.listen_host),"0.0.0.0");
        config.listen_port=4445;
        snprintf(config.backend_host,sizeof(config.backend_host),"example.com");
        config.backend_port=80;
        config.max_connection=100;
        config.timeout=30;
        config.keep_alive=1;
    }

    initThreadPool(&pool,MAX_THREADS);
    start_server();
    shutdownThreadPool(&pool);

    close_log();
    return 0;
}
