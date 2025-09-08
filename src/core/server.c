#include "../include/server.h"
#include "../include/client.h"
#include "../include/proxy.h"
#include "../include/config.h"
#include <stdio.h>
#include <string.h>
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

int server_init(const char *listen_host, int port, SOCKET *server_fd) {
    WSADATA wsa;
    struct sockaddr_in server_addr;
    // khoi tao winsock de su dung socket
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSA loi\n");
        return -1;
    }

    *server_fd = socket(AF_INET, SOCK_STREAM, 0); // tao socket tcp/ipv4
    if (*server_fd == INVALID_SOCKET) {
        printf("Socket loi\n");
        WSACleanup();
        return -1;
    }

    // Cho phép reuse address
    int opt = 1;
    setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    
    // Parse listen host
    if (strcmp(listen_host, "0.0.0.0") == 0) {
        server_addr.sin_addr.s_addr = INADDR_ANY; // nhan tat ca ket noi
    } else {
        unsigned long addr = inet_addr(listen_host);
        if (addr == INADDR_NONE) {
            printf("Invalid listen host: %s\n", listen_host);
            closesocket(*server_fd);
            WSACleanup();
            return -1;
        }
        server_addr.sin_addr.s_addr = addr;
    }
    
    server_addr.sin_port = htons(port); //Host TO Network Short để chuyển thành network byte order

    if (bind(*server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind loi\n");
        closesocket(*server_fd);
        WSACleanup();
        return -1;
    }

    if (listen(*server_fd, 5) == SOCKET_ERROR) {
        printf("Listen loi\n");
        closesocket(*server_fd);
        WSACleanup();
        return -1;
    }

    return 0;
}

void start_server(const Proxy_Config *config) {
    SOCKET server_fd, client_fd;
    struct sockaddr_in client_addr;
    int addrlen = sizeof(client_addr);

    // Khởi tạo server socket
    if (server_init(config->listen_host, config->listen_port, &server_fd) < 0) {
        return;
    }

    printf("Proxy server dang chay %s:%d -> %s:%d\n", 
           config->listen_host, config->listen_port, 
           config->backend_host, config->backend_port);
    
    printf("Max connections: %d, Timeout: %d, Keep-alive: %d\n",
           config->max_connection, config->timeout, config->keep_alive);

    // Main loop - accept và handle connections
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
        if (client_fd == INVALID_SOCKET) {
            continue;
        }

        // Handle client connection với config
        handle_client(client_fd, config);
    }

    server_cleanup(server_fd);
}

void server_cleanup(SOCKET server_fd) {
    closesocket(server_fd);
    WSACleanup();
}