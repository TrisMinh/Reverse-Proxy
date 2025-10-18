#include "../include/http_processor.h"
#include "../include/logger.h"
#include <stdio.h>
#include <string.h>

int validate_http_request(const char *request) {
    if (!request || strlen(request) < 10) return 0;
    if (!strstr(request, " HTTP/1.")) return 0;
    const char *hdr_end = strstr(request, "\r\n\r\n");
    if (!hdr_end) return 0;
    for (const char *p = request; p < hdr_end; ++p)
    if (*p == '\n' && (p == request || *(p-1) != '\r')) return 0;
    
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
                "Host: %s\r\n"
                "X-Forwarded-For: %s\r\n"
                "X-Forwarded-Host: %s\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n" 
                "%.*s",
                before_host, original_req,
                original_host,
                client_ip,
                original_host,
                total_len - after_host_start, original_req + after_host_start);
            
            return (written < max_len) ? 0 : -1;
        }
    }
    
    // Không có Host header
    return -1;
}

int modify_response_headers(const char *original_resp, int original_len, char *modified_resp, int max_len, const char *backend_host, int backend_port, const char *proxy_host, int proxy_port) {
    // Tìm vị trí kết thúc header
    const char *header_end = NULL;
    for (int i = 0; i < original_len - 3; i++) {
        if (original_resp[i] == '\r' && original_resp[i+1] == '\n' &&
            original_resp[i+2] == '\r' && original_resp[i+3] == '\n') {
            header_end = original_resp + i + 4;
            break;
        }
    }

    if (!header_end) {
        if (original_len > max_len) return -1;
        memcpy(modified_resp, original_resp, original_len);
        return original_len;
    }

    int header_len = header_end - original_resp;
    int body_len   = original_len - header_len;

    // copy header để sửa
    char header_buf[8192];
    if (header_len >= (int)sizeof(header_buf)) {
        // header quá dài
        if (original_len > max_len) return -1;
        memcpy(modified_resp, original_resp, original_len);
        return original_len;
    }
    memcpy(header_buf, original_resp, header_len);
    header_buf[header_len] = '\0';

    //Đổi Server header
    char *server_hdr = strstr(header_buf, "Server:");
    if (!server_hdr) server_hdr = strstr(header_buf, "server:");
    if (server_hdr) {
        char *line_end = strstr(server_hdr, "\r\n");
        if (line_end) {
            char temp[8192];
            snprintf(temp, sizeof(temp),
                     "%.*sServer: PBL\r\n%s",
                     (int)(server_hdr - header_buf), header_buf,
                     line_end + 2);
            if (strlen(temp) < sizeof(header_buf)) {
                strncpy(header_buf, temp, sizeof(header_buf)-1);
                header_buf[sizeof(header_buf)-1] = '\0';
            }
        }
    } else {
        // thêm mới nếu không có
        char *end_status = strstr(header_buf, "\r\n");
        if (end_status) {
            char temp[8192];
            snprintf(temp, sizeof(temp),
                     "%.*s\r\nServer: PBL\r\n%s",
                     (int)(end_status - header_buf), header_buf,
                     end_status + 2);
            if (strlen(temp) < sizeof(header_buf)) {
                strncpy(header_buf, temp, sizeof(header_buf)-1);
                header_buf[sizeof(header_buf)-1] = '\0';
            }
        }
    }

    char *conn_hdr = strstr(header_buf, "Connection:");
    if (!conn_hdr) conn_hdr = strstr(header_buf, "connection:");
    if (conn_hdr) {
        char *line_end = strstr(conn_hdr, "\r\n");
        if (line_end) {
            char temp[8192];
            snprintf(temp, sizeof(temp),
                     "%.*sConnection: close\r\n%s",
                     (int)(conn_hdr - header_buf), header_buf,
                     line_end + 2);
            if (strlen(temp) < sizeof(header_buf)) {
                strncpy(header_buf, temp, sizeof(header_buf)-1);
                header_buf[sizeof(header_buf)-1] = '\0';
            }
        }
    } else {
        // Nếu không có header Connection thì thêm vào sau status line
        char *first_crlf = strstr(header_buf, "\r\n");
        if (first_crlf) {
            char temp[8192];
            snprintf(temp, sizeof(temp),
                     "%.*s\r\nConnection: close\r\n%s",
                     (int)(first_crlf - header_buf), header_buf,
                     first_crlf + 2);
            if (strlen(temp) < sizeof(header_buf)) {
                strncpy(header_buf, temp, sizeof(header_buf)-1);
                header_buf[sizeof(header_buf)-1] = '\0';
            }
        }
    }

    //Sửa Location header
    char *location = strstr(header_buf, "Location: http://");
    if (!location) location = strstr(header_buf, "location: http://");
    if (location) {
        char *location_end = strstr(location, "\r\n");
        if (location_end) {
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
            } else if (strncmp(location_value, backend_url_no_port, strlen(backend_url_no_port)) == 0) {
                need_fix = 1;
                path_to_keep = location_value + strlen(backend_url_no_port);
            }

            if (need_fix) {
                char proxy_url[128];
                snprintf(proxy_url, sizeof(proxy_url), "http://%s:%d", proxy_host, proxy_port);

                char fixed_resp[8192];
                int before_len = location_value - header_buf;
                int after_start = location_end - header_buf;

                snprintf(fixed_resp, sizeof(fixed_resp), "%.*s%s%s%s", before_len, header_buf, proxy_url, path_to_keep, header_buf + after_start);

                if (strlen(fixed_resp) < sizeof(header_buf)) {
                    strncpy(header_buf, fixed_resp, sizeof(header_buf)-1);
                    header_buf[sizeof(header_buf)-1] = '\0';
                }
            }
        }
    }

    //Ghép header + body
    int new_header_len = (int)strlen(header_buf);
    int total_len = new_header_len + body_len;
    if (total_len > max_len) return -1;

    memcpy(modified_resp, header_buf, new_header_len);
    memcpy(modified_resp + new_header_len, original_resp + header_len, body_len);

    return total_len;
}


char* extract_host_from_request(const char *request, char *host_buffer, int buffer_size) {
    if (!request || !host_buffer || buffer_size <= 0) return NULL;
    
    char *header_end = strstr(request, "\r\n\r\n");
    if (!header_end) return NULL;
    
    char *host_start = strstr(request, "Host:");
    if (!host_start) {
        host_start = strstr(request, "host:");
    }
    if (!host_start || host_start >= header_end) return NULL;
    
    host_start += 5; // Skip
    while (*host_start == ' ' || *host_start == '\t') host_start++;
    
    char *host_line_end = strstr(host_start, "\r\n");
    if (!host_line_end) return NULL;
    
    int host_len = host_line_end - host_start;
    if (host_len <= 0 || host_len >= buffer_size) return NULL;
    
    strncpy(host_buffer, host_start, host_len);
    host_buffer[host_len] = '\0';
    
    // Loại bỏ port nếu có
    char *port_pos = strchr(host_buffer, ':');
    if (port_pos) {
        *port_pos = '\0';
    }
    
    return host_buffer;
}
