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

// Xử lý response từ backend trước khi gửi về client
void modify_response_headers(const char *original_resp, char *modified_resp, int max_len, const char *backend_host, int backend_port, const char *proxy_host, int proxy_port) {
    
    strcpy(modified_resp, original_resp);
    
    char *location = strstr(modified_resp, "Location: http://");
    if (!location) {
        location = strstr(modified_resp, "location: http://");
    }
    
    if (!location) {
        return;
    }
    
    char *location_end = strstr(location, "\r\n");
    if (!location_end) {
        return;
    }
    
    char *location_value = location + 9;
    while (*location_value == ' ') location_value++;
    
    char backend_url_with_port[128];
    char backend_url_no_port[128];
    snprintf(backend_url_with_port, sizeof(backend_url_with_port), "http://%s:%d", backend_host, backend_port);
    snprintf(backend_url_no_port, sizeof(backend_url_no_port), "http://%s", backend_host);
    
    int need_fix = 0;
    char *path_to_keep = NULL;
    
    if (strncmp(location_value, backend_url_with_port, strlen(backend_url_with_port)) == 0) {
        need_fix = 1;
        path_to_keep = location_value + strlen(backend_url_with_port);
    }
    else if (strncmp(location_value, backend_url_no_port, strlen(backend_url_no_port)) == 0) {
        need_fix = 1;
        path_to_keep = location_value + strlen(backend_url_no_port);
    }
    
    if (need_fix) {
        char proxy_url[128];
        snprintf(proxy_url, sizeof(proxy_url), "http://%s:%d", proxy_host, proxy_port);
        
        char new_response[8192];
        int before_len = location_value - modified_resp;
        int after_start = location_end - modified_resp;
        
        snprintf(new_response, sizeof(new_response), "%.*s%s%s%s",
                before_len, modified_resp,
                proxy_url, path_to_keep,
                modified_resp + after_start);
        
        if (strlen(new_response) < max_len) {
            strcpy(modified_resp, new_response);
        }
    }
}
