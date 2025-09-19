#ifndef SERVER_H
#define SERVER_H

#include <winsock2.h>
#include "config.h"

int server_init(const char *listen_host, int port, SOCKET *server_fd);
void start_server();
void server_cleanup(SOCKET server_fd);

void handle_client_task(void *arg);
#endif