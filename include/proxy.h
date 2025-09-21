#ifndef PROXY_H
#define PROXY_H

#include "config.h"
#include <winsock2.h>

void handle_client(SOCKET client_fd, const Proxy_Config *config);

#endif
