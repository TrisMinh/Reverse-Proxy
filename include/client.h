#ifndef CLIENT_H
#define CLIENT_H

#include <winsock2.h>
#include "config.h"

void handle_client(SOCKET client_fd, const Proxy_Config *config);

#endif

