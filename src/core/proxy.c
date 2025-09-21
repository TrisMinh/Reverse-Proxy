#include "../include/proxy.h"
#include "../include/client.h"
#include "../include/filter_chain.h"
#include "../include/logger.h"

#include "../include/ssl_utils.h"

extern SSL_CTX *global_ssl_ctx;

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

    char extracted_host[256];
    //Lấy Host:.... trong http request
    char *host_from_request = extract_host_from_request(recv_buffer, extracted_host, sizeof(extracted_host));
    if (!host_from_request || strlen(host_from_request) == 0) {
        log_message("ERROR", "Could not extract host from request");
        const char *bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(client_fd, bad, (int)strlen(bad), 0);
        closesocket(client_fd);
        return;
    }

    //Tìm cấu hình tương ứng vs domain 
    const ProxyRoute *rec = find_proxy_routes(host_from_request);
    if (!rec) {
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "No backend found for: %s", host_from_request);
        log_message("ERROR", log_buf);
        const char *notfound = "HTTP/1.1 502 bad gateway\r\nContent-Length: 0\r\n\r\n";
        send(client_fd, notfound, (int)strlen(notfound), 0);
        closesocket(client_fd);
        return;
    }

    char target_backend_host[256];
    strncpy(target_backend_host, rec->backend_host, sizeof(target_backend_host)-1);
    target_backend_host[sizeof(target_backend_host)-1] = '\0';

    // Xem thử backend này sài port 80 hay 443
    detect_backend_protocol((ProxyRoute*)rec); 
    int target_backend_port = rec->backend_port;
    {
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "Domain routing: %s -> %s:%d", host_from_request, target_backend_host, target_backend_port);
        log_message("INFO", log_buf);
    }
    
    // Test để địa chỉ 127.0.0.1
    if (modify_request_headers(recv_buffer, send_buffer, sizeof(send_buffer), target_backend_host, target_backend_port, host_from_request) != 0) {
        //log
        log_message("WARN", "Failed to modify HTTP headers, forwarding original request");

        strncpy(send_buffer, recv_buffer, sizeof(send_buffer) - 1);  // modify fail thì cứ giữ nguyên request
        send_buffer[sizeof(send_buffer) - 1] = '\0';
    }
    // (2)
    // Ket noi den backend
   //Thêm mới: kết nối http/https
    if (rec->is_https) {
        BackendConnection backend_conn;
        if (connect_to_backend_https(target_backend_host, target_backend_port, &backend_conn, global_ssl_ctx) != 0) {
            log_message("ERROR", "Failed to connect to HTTPS backend");
            const char *unavailable = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            send(client_fd, unavailable, (int)strlen(unavailable), 0);
            closesocket(client_fd);
            return;
        }

        // Gửi request qua TLS
        SSL_write(backend_conn.ssl, send_buffer, (int)strlen(send_buffer));

        // Nhận response từ TLS
        while ((bytes_recv = SSL_read(backend_conn.ssl, recv_buffer, sizeof(recv_buffer) - 1)) > 0) {
            // recv_buffer[bytes_recv] = '\0'; // kết thúc chuỗi để xử lý

            char modified_resp[BUFFER_SIZE];
            // Sửa lại header trước khi gửi về client
            int new_len = modify_response_headers(recv_buffer, bytes_recv, modified_resp, sizeof(modified_resp),target_backend_host, target_backend_port, config->listen_host, config->listen_port);

            send(client_fd, modified_resp, new_len, 0);
        }

        SSL_shutdown(backend_conn.ssl);
        SSL_free(backend_conn.ssl);
        closesocket(backend_conn.sock);

    } else {

        //đoạn cũ
        SOCKET backend_fd;
        if (connect_to_backend(target_backend_host, target_backend_port, &backend_fd) != 0) {
            log_message("ERROR", "Failed to connect to HTTP backend");
            const char *unavailable = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            send(client_fd, unavailable, (int)strlen(unavailable), 0);
            closesocket(client_fd);
            return;
        }

        send(backend_fd, send_buffer, (int)strlen(send_buffer), 0);

        while ((bytes_recv = recv(backend_fd, recv_buffer, sizeof(recv_buffer) - 1, 0)) > 0) {
            // recv_buffer[bytes_recv] = '\0'; // kết thúc chuỗi để xử lý

            char modified_resp[BUFFER_SIZE];
            int new_len = modify_response_headers(recv_buffer, bytes_recv,modified_resp, sizeof(modified_resp),target_backend_host, target_backend_port, config->listen_host, config->listen_port);

            send(client_fd, modified_resp, new_len, 0);
        }

        closesocket(backend_fd);
    }

    // Dong ket noi
    closesocket(client_fd);
    // closesocket(backend_fd);
}

int detect_backend_protocol(ProxyRoute *rec) {
    // // Nếu đã test 1 lần r thì lần sau khỏi test
    if (rec->is_https == 1 || rec->is_https == 0) {
        return rec->is_https;
    }

    // Test trên port 443
    int ok = test_https_handshake(global_ssl_ctx, rec->backend_host, 443);
    if (ok) {
        rec->backend_port = 443;
        rec->is_https = 1;
    } else {
        rec->backend_port = 80;
        rec->is_https = 0;
    }

    return rec->is_https;
}
