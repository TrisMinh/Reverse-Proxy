#ifndef CLIENT_H
#define CLIENT_H

#include <winsock2.h>
#include "config.h"

int connect_to_backend(const char *host, int port, SOCKET *out_sock);

#endif

