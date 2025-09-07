#include "../include/http_processor.h"
#include <stdio.h>
#include <string.h>

int validate_http_request(const char *request) {
    if (!request || strlen(request) < 10) return 0;
    if (!strstr(request, " HTTP/1.")) return 0;
    // Kiểm tra request có hợp lệ không (basic validation)
    if (strncmp(request, "GET ", 4) == 0 ||
        strncmp(request, "POST ", 5) == 0 ||
        strncmp(request, "PUT ", 4) == 0 ||
        strncmp(request, "DELETE ", 7) == 0 ||
        strncmp(request, "HEAD ", 5) == 0 ||
        strncmp(request, "OPTIONS ", 8) == 0 ||
        strncmp(request, "PATCH ", 6) == 0) {
        return 1;
    }
    return 0;
}

int modify_request_headers(const char *original_req, char *modified_req, int max_len, const char *backend_host, int backend_port, const char *client_ip) {
    
    char *header_end = strstr(original_req, "\r\n\r\n");
    if (!header_end) {
        //header k hợp lệ hủy kết nối
        return -1;
    }

    char original_host[256] = "";

    char *host_start = strstr(original_req, "Host:");
    if (!host_start) {
        host_start = strstr(original_req, "host:");
    }
    if (host_start && host_start < header_end) {
        host_start += 5;
        while (*host_start == ' ') host_start++;
        
        char *host_line_end = strstr(host_start, "\r\n");
        if (host_line_end) {
            int host_len = host_line_end - host_start;
            if (host_len > 0 && host_len < sizeof(original_host)) {
                strncpy(original_host, host_start, host_len);
                original_host[host_len] = '\0';
            }
        }
    }

    //Tìm và trỏ đến Host trong chuỗi
    host_start = strstr(original_req, "Host:");
    if (!host_start) {
        host_start = strstr(original_req, "host:");
    }
    
    if (host_start && host_start < header_end) {
        char *host_line_end = strstr(host_start, "\r\n");
        if (host_line_end) {
            // Tạo request mới: before Host + new headers + after Host + body
            int before_host = host_start - original_req;
            int after_host_start = host_line_end - original_req + 2;
            int total_len = strlen(original_req);
            
            int written = snprintf(modified_req, max_len, 
                "%.*s"
                "Host: %s:%d\r\n"
                "X-Forwarded-For: %s\r\n"
                "X-Forwarded-Host: %s\r\n"
                "X-Forwarded-Proto: http\r\n"
                "%.*s",
                before_host, original_req,
                backend_host, backend_port,
                client_ip,
                original_host,
                total_len - after_host_start, original_req + after_host_start);
            
            return (written < max_len) ? 0 : -1;
        }
    }
    
    // Không có Host header
    return -1;
}