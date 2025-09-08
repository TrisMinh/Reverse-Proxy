#include "../include/proxy.h"
#include "../include/client.h"
#include "../include/filter_chain.h"
#include "../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 8192 // 8KB

void handle_client(SOCKET client_fd, const Proxy_Config *config) {
    // Flow như sau
    // Doc request tu client   (1)
    // Gui request den backend (2)
    // Doc response tu backend va gui den client (3)
    char recv_buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];
    int total = 0;
    int bytes_recv;
    // Doc headers tu client (1)
    while (total < (int)sizeof(recv_buffer) - 1) { // mỗi lần ghi tiếp tại vị trí total thì size còn lại giảm -1 - total
        bytes_recv = recv(client_fd, recv_buffer + total, BUFFER_SIZE - 1 - total, 0); //mode 0 la default, mode là các cờ điều khiển
        if ( bytes_recv <=0 ) {
            log_message("ERROR", "Failed to receive data from client");
            closesocket(client_fd);
            return;
        }

        total += bytes_recv;
        recv_buffer[total] = '\0'; // \0 đặt điểm kết thúc để sài các hàm str

        if (strstr(recv_buffer, "\r\n\r\n")) {// strstr tìm chuỗi con, \r\n\r\n la kết thúc header
            break;
        } 
    }

    if (total == BUFFER_SIZE - 1) {
        log_message("ERROR", "Buffer overflow");
        closesocket(client_fd);
        return;
    }

    if (!validate_http_request(recv_buffer)) { // kiểm tra tính hợp lệ của header
        //log
        log_message("WARN", "Received invalid HTTP request from client");
        
        const char *bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"; // báo lỗi
        send(client_fd, bad, (int)strlen(bad), 0);
        closesocket(client_fd);
        return;
    }
    
    // Test để địa chỉ 127.0.0.1
    if (modify_request_headers(recv_buffer, send_buffer, sizeof(send_buffer), config->backend_host, config->backend_port, "127.0.0.1") != 0) {
        //log
        log_message("WARN", "Failed to modify HTTP headers, forwarding original request");

        strncpy(send_buffer, recv_buffer, sizeof(send_buffer) - 1);  // modify fail thì cứ giữ nguyên request
        send_buffer[sizeof(send_buffer) - 1] = '\0';
    }
    // (2)
    // Ket noi den backend
    SOCKET backend_fd;
    if (connect_to_backend(config->backend_host, config->backend_port, &backend_fd) != 0) {
        //log
        log_message("ERROR", "Failed to connect to backend server");

        const char *unavailable = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        send(client_fd, unavailable, (int)strlen(unavailable), 0);
        closesocket(client_fd);
        return;
    }

    // Gui request da modify den backend
    send(backend_fd, send_buffer, (int)strlen(send_buffer), 0);
    // (3)
    // Nhan response tu backend va gui den client
    while ((bytes_recv = recv(backend_fd, recv_buffer, sizeof(recv_buffer), 0)) > 0) {
        send(client_fd, recv_buffer, bytes_recv, 0);
    }

    // Dong ket noi
    closesocket(client_fd);
    closesocket(backend_fd);
}