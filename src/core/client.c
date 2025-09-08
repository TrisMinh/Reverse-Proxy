#include "../include/client.h"
#include "../include/http_processor.h"
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define BUFFER_SIZE 8192

int connect_to_backend(const char *host, int port, SOCKET *out_sock) {
    struct sockaddr_in backend_addr;

    *out_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*out_sock == INVALID_SOCKET) {
        return -1;
    }

    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(port);
    unsigned long addr = inet_addr(host);
    if (addr == INADDR_NONE) {
        closesocket(*out_sock);
        return -1;
    }
    backend_addr.sin_addr.s_addr = addr;

    if (connect(*out_sock, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) == SOCKET_ERROR) {
        closesocket(*out_sock);
        return -1;
    }

    return 0;
}

