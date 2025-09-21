#ifndef CLIENT_H
#define CLIENT_H

#include <winsock2.h>
#include "config.h"
#include <openssl/ssl.h>

typedef struct {
    SOCKET sock;
    SSL *ssl;
} BackendConnection;

int connect_to_backend(const char *host, int port, SOCKET *out_sock);
int connect_to_backend_https(const char *host, int port, BackendConnection *conn, SSL_CTX *ctx);

#endif

