#include "client.h"
#include "logger.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

int connect_to_backend(const char *host, int port, SOCKET *backend_fd) {
    *backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*backend_fd == INVALID_SOCKET) {
        log_message("ERROR","Create backend socket failed");
        return -1;
    }

    struct sockaddr_in addr;
    struct hostent *he = gethostbyname(host);
    if (he == NULL) {
        log_message("ERROR","DNS lookup failed");
        closesocket(*backend_fd);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);


    if (connect(*backend_fd,(struct sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR) {
        log_message("ERROR","Connect backend failed");
        closesocket(*backend_fd);
        return -1;
    }

    return 0;
}


//kết nối https 
int connect_to_backend_https(const char *host, int port, BackendConnection *conn, SSL_CTX *ctx) {
    struct addrinfo hints, *res, *p;
    char port_str[16];
    int rv;

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // chỉ ipv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    if ((rv = getaddrinfo(host, port_str, &hints, &res)) != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        conn->sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (conn->sock == INVALID_SOCKET) continue;

        if (connect(conn->sock, p->ai_addr, (int)p->ai_addrlen) == 0) {
            conn->ssl = SSL_new(ctx);
            SSL_set_fd(conn->ssl, (int)conn->sock);

            if (!SSL_set_tlsext_host_name(conn->ssl, host)) {
                SSL_free(conn->ssl);
                closesocket(conn->sock);
                continue;
            }

            if (SSL_connect(conn->ssl) <= 0) {
                SSL_free(conn->ssl);
                closesocket(conn->sock);
                continue;
            }

            freeaddrinfo(res);
            return 0;
        }

        closesocket(conn->sock);
    }

    freeaddrinfo(res);
    return -1;
}
