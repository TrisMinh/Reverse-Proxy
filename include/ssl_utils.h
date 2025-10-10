#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX* init_ssl_ctx();
void cleanup_ssl_ctx(SSL_CTX *ctx);

int test_https_handshake(SSL_CTX *ctx, const char *host, int port);

SSL_CTX* init_ssl_server_ctx();
void free_ssl_cert_cache();


#endif
