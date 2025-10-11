#include "../include/proxy.h"
#include "../include/client.h"
#include "../include/filter_chain.h"
#include "../include/logger.h"
#include "../include/config.h"

#include "../include/ssl_utils.h"
#include "../include/acme_webroot.h"
#include <openssl/ssl.h>

#define CLIENT_READ(buf, len)   ((ssl) ? SSL_read(ssl, buf, len) : recv(client_fd, buf, len, 0))
#define CLIENT_WRITE(buf, len)  ((ssl) ? SSL_write(ssl, buf, len) : send(client_fd, buf, len, 0))

extern SSL_CTX *global_ssl_ctx;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 8192
#define HEADER_BUFFER_SIZE (BUFFER_SIZE * 4)

static int send_all(SOCKET s, const char *buf, int len, SSL *ssl) {
    int sent = 0;
    while (sent < len) {
        int n = (ssl) ? SSL_write(ssl, buf + sent, len - sent)
                      : send(s, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

// Bật TCP_NODELAY để tránh Nagle delay
static void set_tcp_nodelay(SOCKET sock) {
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
}

static int handle_acme_if_needed(SOCKET client_fd, const char *req_buffer, const Proxy_Config *config) {
    char path[1024] = {0};
    const char *sp1 = strchr(req_buffer, ' ');
    const char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (sp1 && sp2) {
        int len = (int)(sp2 - (sp1 + 1));
        if (len > 0 && len < (int)sizeof(path)) {
            memcpy(path, sp1 + 1, len);
            path[len] = '\0';
        }
    }

    const char *webroot = (config && config->acme_webroot[0]) ? config->acme_webroot : "D:\\acme-webroot";

    if (acme_try_handle_with_root(client_fd, NULL, path, webroot)) {
        return 1;
    }
    return 0;
}

// Đọc header request từ client
static int read_request_headers(SOCKET cfd, SSL *ssl, char *buf, int bufsz) {
    int total = 0;
    while (total < bufsz - 1) {
        int n = ssl ? SSL_read(ssl, buf + total, bufsz - 1 - total)
                    : recv(cfd, buf + total, bufsz - 1 - total, 0);
        if (n <= 0) return -1;
        total += n;
        buf[total] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    if (total == bufsz - 1) return -2; // tràn buffer header
    return total;
}

// Gửi phần body đã đọc sẵn
static void forward_already_read_body(const char *req_buf, int total_read, SOCKET backend_fd, SSL *backend_ssl) {
    const char *end = strstr(req_buf, "\r\n\r\n");
    if (!end) return;
    int hdr_len = (int)(end - req_buf) + 4;
    int body_len = total_read - hdr_len;
    if (body_len > 0) {
        send_all(backend_fd, req_buf + hdr_len, body_len, backend_ssl);
    }
}

// Kết nối tới backend theo + TCP_NODELAY
static int connect_backend_auto(const ProxyRoute *rec, const char *host, int port, SOCKET *fd_out, SSL **ssl_out) {
    SOCKET fd = INVALID_SOCKET;
    SSL *bssl = NULL;

    if (rec->is_https) {
        BackendConnection c;
        if (connect_to_backend_https(host, port, &c, global_ssl_ctx) != 0) return -1;
        fd = c.sock; bssl = c.ssl;
    } else {
        if (connect_to_backend(host, port, &fd) != 0) return -1;
    }

    set_tcp_nodelay(fd);
    *fd_out = fd;
    *ssl_out = bssl;
    return 0;
}

static void send_quick_error(SOCKET cfd, SSL *ssl, const char *status) {
    char resp[128];
    int n = snprintf(resp, sizeof(resp), "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
    if (n < 0) return;
    send_all(cfd, resp, n, ssl);
}

void handle_client(SOCKET client_fd, SSL *ssl, const Proxy_Config *config) {
    // Flow như sau
    // Doc request tu client   (1)
    // Gui request den backend (2)
    // Doc response tu backend va gui den client (3)
    char recv_buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];
    int total = 0;

    int use_ssl = 0;
    SOCKET backend_fd = INVALID_SOCKET;
    SSL *backend_ssl = NULL;

    set_tcp_nodelay(client_fd); // giảm delay TCP

    // Doc headers tu client
    total = read_request_headers(client_fd, ssl, recv_buffer, (int)sizeof(recv_buffer));
    if (total < 0) {
        if (total == -2) {
            log_message("ERROR", "Buffer overflow");
        } else {
            log_message("ERROR", "Failed to receive data from client");
        }
        goto cleanup;
    }

    if (!validate_http_request(recv_buffer)) { // kiểm tra tính hợp lệ của header
        log_message("WARN", "Received invalid HTTP request from client");
        send_quick_error(client_fd, ssl, "400 Bad Request");
        goto cleanup;
    }

    if (!ssl && handle_acme_if_needed(client_fd, recv_buffer, config)) {
        goto cleanup;
    }

    char extracted_host[256];
    //Lấy Host:.... trong http request
    char *host_from_request = extract_host_from_request(recv_buffer, extracted_host, sizeof(extracted_host));
    if (!host_from_request || strlen(host_from_request) == 0) {
        log_message("ERROR", "Could not extract host from request");
        send_quick_error(client_fd, ssl, "400 Bad Request");
        goto cleanup;
    }

    //Tìm cấu hình tương ứng vs domain 
    const ProxyRoute *rec = find_proxy_routes(host_from_request);
    if (!rec) {
        char log_buf[512];
        snprintf(log_buf, sizeof(log_buf), "No backend found for: %s", host_from_request);
        log_message("ERROR", log_buf);
        send_quick_error(client_fd, ssl, "502 Bad Gateway");
        goto cleanup;
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
    
    // Modify request
    if (modify_request_headers(recv_buffer, send_buffer, sizeof(send_buffer), target_backend_host, target_backend_port, host_from_request) != 0) {
        log_message("WARN", "Failed to modify HTTP headers, forwarding original request");
        strncpy(send_buffer, recv_buffer, sizeof(send_buffer) - 1);
        send_buffer[sizeof(send_buffer) - 1] = '\0';
    }
    int send_len = (int)strlen(send_buffer);

    //Ket noi den backend
    if (connect_backend_auto(rec, target_backend_host, target_backend_port, &backend_fd, &backend_ssl) != 0) {
        log_message("ERROR", "Failed to connect to backend");
        send_quick_error(client_fd, ssl, "502 Bad Gateway");
        goto cleanup;
    }
    use_ssl = (backend_ssl != NULL);

    if (send_all(backend_fd, send_buffer, send_len, use_ssl ? backend_ssl : NULL) != 0) {
        log_message("ERROR", "Failed to send request headers to backend");
    }

    // Gửi phần body còn lại
    forward_already_read_body(recv_buffer, total, backend_fd, use_ssl ? backend_ssl : NULL);

    fd_set fds;
    int header_done = 0;
    int buffered = 0;
    char header_buf[HEADER_BUFFER_SIZE];

    long long content_length = -1;
    int is_chunked = 0;
    long long bytes_sent_body = 0;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(backend_fd, &fds);
        int maxfd = (client_fd > backend_fd ? client_fd : backend_fd) + 1;

        int rv = select(maxfd, &fds, NULL, NULL, NULL);
        if (rv <= 0) break;

        // CLIENT → BACKEND
        if (FD_ISSET(client_fd, &fds)) {
            int n = (ssl ? SSL_read(ssl, recv_buffer, sizeof(recv_buffer))
                        : recv(client_fd, recv_buffer, sizeof(recv_buffer), 0));
            if (n <= 0) break;
            if (send_all(backend_fd, recv_buffer, n, use_ssl ? backend_ssl : NULL) != 0) break;
        }

        // BACKEND → CLIENT
        if (FD_ISSET(backend_fd, &fds)) {
            int n = use_ssl
                ? SSL_read(backend_ssl, recv_buffer, sizeof(recv_buffer))
                : recv(backend_fd, recv_buffer, sizeof(recv_buffer), 0);
            if (n <= 0) break;
            recv_buffer[n] = '\0';

            if (!header_done) {
                if (buffered + n > HEADER_BUFFER_SIZE) {
                    log_message("ERROR", "Header too large from backend");
                    send_quick_error(client_fd, ssl, "502 Bad Gateway");
                    goto cleanup;
                }
                memcpy(header_buf + buffered, recv_buffer, n);
                buffered += n;
                header_buf[buffered] = '\0';

                char *hdr_end = strstr(header_buf, "\r\n\r\n");
                if (hdr_end) {
                    int header_len = (int)(hdr_end - header_buf) + 4;
                    int body_len   = buffered - header_len;

                    char *cl = strstr(header_buf, "Content-Length:");
                    if (!cl) cl = strstr(header_buf, "content-length:");
                    if (cl && cl < hdr_end)
                        content_length = atoll(cl + 15);

                    char *te = strstr(header_buf, "Transfer-Encoding:");
                    if (!te) te = strstr(header_buf, "transfer-encoding:");
                    if (te && te < hdr_end && strstr(te, "chunked"))
                        is_chunked = 1;

                    char modified[HEADER_BUFFER_SIZE];
                    int new_len = modify_response_headers(header_buf, header_len, modified, sizeof(modified), target_backend_host, target_backend_port, config->listen_host, config->listen_port);
                    if (new_len > 0)
                        send_all(client_fd, modified, new_len, ssl);
                    else
                        send_all(client_fd, header_buf, header_len, ssl);

                    if (body_len > 0)
                        send_all(client_fd, header_buf + header_len, body_len, ssl);

                    header_done = 1;
                    buffered = 0;

                    bytes_sent_body = body_len;
                }
            } else {
                if (send_all(client_fd, recv_buffer, n, ssl) != 0)
                    break;

                bytes_sent_body += n;

                if (content_length >= 0) {
                    if (bytes_sent_body >= content_length) {
                        break;
                    }
                } else if (is_chunked) {
                    if (strstr(recv_buffer, "\r\n0\r\n\r\n")) {
                        break;
                    }
                }
            }
        }
    }

cleanup:
    if (backend_ssl) {
        SSL_shutdown(backend_ssl);
        SSL_free(backend_ssl);
        backend_ssl = NULL;
    }
    if (backend_fd != INVALID_SOCKET) {
        closesocket(backend_fd);
        backend_fd = INVALID_SOCKET;
    }
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
    }
    if (client_fd != INVALID_SOCKET) {
        closesocket(client_fd);
        client_fd = INVALID_SOCKET;
    }
    return;
}

int detect_backend_protocol(ProxyRoute *rec) {
    if (rec->is_https == 0 || rec->is_https == 1) {
        return rec->is_https;
    }

    if (rec->backend_port > 0) {
        if (rec->backend_port == 443) {
            rec->is_https = 1;
            return 1;
        }
        int ok = test_https_handshake(global_ssl_ctx, rec->backend_host, rec->backend_port);
        rec->is_https = ok ? 1 : 0;
        return rec->is_https;
    }

    if (test_https_handshake(global_ssl_ctx, rec->backend_host, 443)) {
        rec->backend_port = 443;
        rec->is_https = 1;
    } else {
        rec->backend_port = 80;
        rec->is_https = 0;
    }
    return rec->is_https;
}
