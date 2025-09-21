#ifndef HTTP_PROCESSOR_H
#define HTTP_PROCESSOR_H

int validate_http_request(const char *request);
int modify_request_headers(const char *original_req, char *modified_req, int max_len,const char *backend_host, int backend_port, const char *client_ip);
int modify_response_headers(const char *original_resp, int original_len, char *modified_resp, int max_len, const char *backend_host, int backend_port, const char *proxy_host, int proxy_port);

// Thêm hàm extract domain từ HTTP request
char* extract_host_from_request(const char *request, char *host_buffer, int buffer_size);

#endif