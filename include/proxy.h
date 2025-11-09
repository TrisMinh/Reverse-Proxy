#ifndef PROXY_H
#define PROXY_H

#include "config.h"
#include "http_processor.h"
#include "proxy_routes.h"
#include <openssl/ssl.h>
#include <winsock2.h>

void handle_client(SOCKET client_fd, SSL *ssl, const Proxy_Config *config);

int acme_middleware_handle(SOCKET client_fd, const char *req_buffer, const Proxy_Config *cfg);

int detect_backend_protocol(ProxyRoute *rec);
int get_client_ip(SOCKET fd, char *out, size_t out_len);

#endif
