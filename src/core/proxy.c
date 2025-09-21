#include "proxy.h"
#include "client.h"
#include "logger.h"
#include "../include/http_processor.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#define BUF_SIZE 8192

void handle_client(SOCKET client_fd, const Proxy_Config *config) {
    char buf[BUF_SIZE];
    int n;

    SOCKET backend_fd;
    if (connect_to_backend(config->backend_host, config->backend_port, &backend_fd) != 0) {
        closesocket(client_fd);
        return;
    }

    fd_set fds;
    int first_request = 1;   // chỉ sửa headers cho request đầu tiên

    while (1) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(backend_fd, &fds);
        int maxfd = (client_fd > backend_fd ? client_fd : backend_fd) + 1;
        int rv = select(maxfd, &fds, NULL, NULL, NULL);
        if (rv <= 0) break;

        // ──────────── CLIENT → BACKEND ────────────
        if (FD_ISSET(client_fd, &fds)) {
            n = recv(client_fd, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';  // thêm null terminator

            if (first_request) {
                first_request = 0;

                // Validate HTTP request
                if (!validate_http_request(buf)) {
                    log_message("ERROR", "Invalid HTTP request");
                    break;
                }

                // Lấy IP client (nếu cần: truyền từ server.c vào handle_client)
                const char *client_ip = "127.0.0.1";

                // Chỉnh sửa headers
                char modified_req[BUF_SIZE * 2];
                if (modify_request_headers(buf, modified_req, sizeof(modified_req),
                                           config->backend_host,
                                           config->backend_port,
                                           client_ip) == 0) {
                    send(backend_fd, modified_req, strlen(modified_req), 0);
                } else {
                    log_message("ERROR", "Failed to modify request headers");
                    break;
                }
            } else {
                // Các request tiếp theo (body, keep-alive) forward nguyên gốc
                send(backend_fd, buf, n, 0);
            }
        }

        // ──────────── BACKEND → CLIENT ────────────
        if (FD_ISSET(backend_fd, &fds)) {
            n = recv(backend_fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(client_fd, buf, n, 0);
        }
    }

    closesocket(client_fd);
    closesocket(backend_fd);
}
