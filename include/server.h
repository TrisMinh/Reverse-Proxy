#ifndef SERVER_H
#define SERVER_H

#include "config.h"
#include <winsock2.h>

int server_init(const char *host,int port,SOCKET *server_fd);
void start_server();
void server_cleanup(SOCKET server_fd);
void handle_client_task(void *arg);

void start_https_server();
void handle_https_client_task(void *arg);

#endif
