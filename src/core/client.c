#include "../include/client.h"
#include "../include/http_processor.h"
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define BUFFER_SIZE 8192
// client này là của proxy đóng vai trò là client kết nối đến backend
int connect_to_backend(const char *host, int port, SOCKET *out_sock) {
    struct addrinfo hints, *res, *p;
    char port_str[16];
    int rv;

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // chỉ IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    if ((rv = getaddrinfo(host, port_str, &hints, &res)) != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        *out_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (*out_sock == INVALID_SOCKET) continue;

        
        if (connect(*out_sock, p->ai_addr, (int)p->ai_addrlen) == 0) {
            freeaddrinfo(res);
            return 0; // OK
        }

        closesocket(*out_sock);
    }

    freeaddrinfo(res);
    return -1;
}


