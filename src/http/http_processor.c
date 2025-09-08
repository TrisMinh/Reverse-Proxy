#include "../include/http_processor.h"
#include <stdio.h>
#include <string.h>

int validate_http_request(const char *request) {
    // Kiểm tra request có hợp lệ không (basic validation)
    if (strncmp(request, "GET ", 4) == 0 ||
        strncmp(request, "POST ", 5) == 0 ||
        strncmp(request, "PUT ", 4) == 0 ||
        strncmp(request, "DELETE ", 7) == 0) {
        return 1;
    }
    return 0;
}

int modify_request_headers(const char *original_req, char *modified_req, int max_len,
                          const char *backend_host, int backend_port, const char *client_ip) {
    
    char *header_end = strstr(original_req, "\r\n\r\n");
    if (!header_end) {
        // Không parse được header, copy nguyên si
        strncpy(modified_req, original_req, max_len - 1);
        modified_req[max_len - 1] = '\0';
        return 0;
    }

    // Tìm và thay Host header
    char *host_start = strstr(original_req, "Host:");
    if (host_start && host_start < header_end) {
        char *host_line_end = strstr(host_start, "\r\n");
        if (host_line_end) {
            // Tạo request mới: trước Host + Host mới + sau Host + body
            int before_host = host_start - original_req;
            int after_host_start = host_line_end - original_req + 2;
            int total_len = strlen(original_req);
            
            int written = snprintf(modified_req, max_len, 
                "%.*s"                              // Phần trước Host header
                "Host: %s:%d\r\n"                  // Host header mới
                "Connection: close\r\n"            // Đảm bảo backend đóng kết nối
                "X-Forwarded-For: %s\r\n"         // IP client thực
                "%.*s",                            // Phần sau Host header
                before_host, original_req,
                backend_host, backend_port,
                client_ip,
                total_len - after_host_start, original_req + after_host_start);
            
            return (written < max_len) ? 0 : -1;
        }
    }
    
    // Không có Host header hoặc không parse được, thêm headers vào cuối
    int written = snprintf(modified_req, max_len, 
        "%.*s"
        "Host: %s:%d\r\n"
        "Connection: close\r\n"
        "X-Forwarded-For: %s\r\n"
        "\r\n%s",
        (int)(header_end - original_req + 2), original_req,
        backend_host, backend_port, client_ip, 
        header_end + 4);
    
    return (written < max_len) ? 0 : -1;
}