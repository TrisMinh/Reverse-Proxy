#include <stdio.h>
#include "../include/client.h"
#include "../include/config.h"
#include "../include/http_processor.h"
// #include "../include/proxy.h"
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

void handle_client(SOCKET client_fd, const Proxy_Config *config) {
    struct sockaddr_in client_addr;
    int addrlen = sizeof(client_addr);
    
    // Set timeout cho client từ config
    DWORD timeout = config->timeout * 1000; // convert to milliseconds
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    // Đọc request từ client
    char buf[8192];
    int n = recv(client_fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        closesocket(client_fd);
        return;
    }
    buf[n] = '\0';

    // Validate request
    if (!validate_http_request(buf)) {
        closesocket(client_fd);
        return;
    }

    // Lấy IP client thực
    getpeername(client_fd, (struct sockaddr*)&client_addr, &addrlen);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    // Modify request headers
    char modified_req[8192];
    if (modify_request_headers(buf, modified_req, sizeof(modified_req), 
                               config->backend_host, config->backend_port, client_ip) < 0) {
        closesocket(client_fd);
        return;
    }

    // Forward request tới backend với retry logic
    int resp_len = 0;
    unsigned char *backend_resp = NULL;
    
    for (int retry = 0; retry <= config->connection_retries; retry++) {
        backend_resp = proxy_forward(config->backend_host, config->backend_port, 
                                   modified_req, &resp_len, config->timeout);
        
        if (backend_resp && resp_len > 0) {
            break; // Success
        }
        
        if (retry < config->connection_retries) {
            printf("Retry %d/%d for backend connection\n", retry + 1, config->connection_retries);
            if (backend_resp) {
                free(backend_resp);
                backend_resp = NULL;
            }
        }
    }

    if (backend_resp && resp_len > 0) {
        // Forward response về client
        send(client_fd, (const char*)backend_resp, resp_len, 0);
        free(backend_resp);
    } else {
        // Trả về lỗi 502 Bad Gateway
        const char *err = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\nBackend Error\r\n";
        send(client_fd, err, (int)strlen(err), 0);
    }

    closesocket(client_fd);
}
