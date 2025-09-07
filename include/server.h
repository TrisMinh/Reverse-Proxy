#ifndef SERVER_H
#define SERVER_H

#include <winsock2.h>
#include "config.h"

int server_init(const char *listen_host, int port, SOCKET *server_fd);
void start_server(const Proxy_Config *config);
void server_cleanup(SOCKET server_fd);

#endif