#include "server.h"
#include "proxy.h"
#include "config.h"
#include "../include/client.h"
#include "threadpool.h"
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>

extern ThreadPool pool;

extern SSL_CTX *global_ssl_server_ctx;

int server_init(const char *listen_host,int port,SOCKET *server_fd){
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2),&wsa)!=0) return -1;

    *server_fd = socket(AF_INET,SOCK_STREAM,0);
    if(*server_fd==INVALID_SOCKET) return -1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = strcmp(listen_host,"0.0.0.0")==0?INADDR_ANY:inet_addr(listen_host);

    int opt=1;
    setsockopt(*server_fd,SOL_SOCKET,SO_REUSEADDR,(char*)&opt,sizeof(opt));

    if(bind(*server_fd,(struct sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR) return -1;
    if(listen(*server_fd,5)==SOCKET_ERROR) return -1;
    return 0;
}

void start_server(){
    SOCKET server_fd;
    Proxy_Config *config = get_config();
    if(server_init(config->listen_host,config->listen_port,&server_fd)<0) return;

    printf("Proxy running %s:%d -> %s:%d\n",config->listen_host,config->listen_port,config->backend_host,config->backend_port);

    while(1){
        struct sockaddr_in client_addr;
        int len = sizeof(client_addr);
        SOCKET client_fd = accept(server_fd,(struct sockaddr*)&client_addr,&len);
        if(client_fd==INVALID_SOCKET) continue;

        SOCKET *arg = malloc(sizeof(SOCKET));
        *arg = client_fd;
        enqueueThreadPool(&pool,handle_client_task,arg);
    }

    server_cleanup(server_fd);
}

void server_cleanup(SOCKET server_fd){
    closesocket(server_fd);
    WSACleanup();
}

void handle_client_task(void *arg){
    SOCKET client_fd = *(SOCKET*)arg;
    free(arg);
    handle_client(client_fd, NULL, get_config());
}

void start_https_server() {
    SOCKET server_fd;
    if (server_init("0.0.0.0", 443, &server_fd) < 0) {
        printf("HTTPS server init failed\n");
        return;
    }

    while (1) {
        struct sockaddr_in client_addr;
        int len = sizeof(client_addr);
        SOCKET client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
        if (client_fd == INVALID_SOCKET)
            continue;

        SSL *ssl = SSL_new(global_ssl_server_ctx);
        if (!ssl) {
            closesocket(client_fd);
            continue;
        }
        SSL_set_fd(ssl, (int)client_fd);

        typedef struct {
            SOCKET client_fd;
            SSL *ssl;
        } SSLClientArg;

        SSLClientArg *arg = malloc(sizeof(SSLClientArg));
        arg->client_fd = client_fd;
        arg->ssl = ssl;

        enqueueThreadPool(&pool, handle_https_client_task, arg);
    }

    server_cleanup(server_fd);
}

void handle_https_client_task(void *arg) {
    typedef struct {
        SOCKET client_fd;
        SSL *ssl;
    } SSLClientArg;

    SSLClientArg *c = (SSLClientArg *)arg;

    SOCKET client_fd = c->client_fd;
    SSL *ssl = c->ssl;
    free(c);

    if (SSL_accept(ssl) <= 0) {
        SSL_free(ssl);
        closesocket(client_fd);
        return;
    }

    handle_client(client_fd, ssl, get_config());
}
