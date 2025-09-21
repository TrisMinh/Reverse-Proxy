#ifndef CLIENT_H
#define CLIENT_H

#include <winsock2.h>

int connect_to_backend(const char *host, int port, SOCKET *backend_fd);

#endif
