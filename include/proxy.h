#ifndef PROXY_H
#define PROXY_H

#include "config.h"
#include "http_processor.h"
#include "proxy_routes.h"
#include <openssl/ssl.h>
#include <winsock2.h>

void handle_client(SOCKET client_fd, SSL *ssl, const Proxy_Config *config);

int acme_middleware_handle(SOCKET client_fd, const char *req_buffer, const Proxy_Config *cfg);

//Check xem backend hiện tại dùng http hay https để chọn cổng
int detect_backend_protocol(ProxyRoute *rec);

#endif
