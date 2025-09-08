#ifndef HTTP_PROCESSOR_H
#define HTTP_PROCESSOR_H

int validate_http_request(const char *request);
int modify_request_headers(const char *original_req, char *modified_req, int max_len,const char *backend_host, int backend_port, const char *client_ip);
void modify_response_headers(const char *original_resp, char *modified_resp, int max_len, const char *original_host, int original_port);

#endif