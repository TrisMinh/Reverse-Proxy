#include "../include/proxy.h"
#include "../include/client.h"
#include "../include/filter_chain.h"
#include "../include/logger.h"
#include "../include/config.h"
#include "../include/cache.h"
#include "../include/request_metrics.h"
#include <ws2tcpip.h>
#include "../include/ssl_utils.h"
#include "../include/acme_webroot.h"
#include "../include/filter_request_guard.h"
#include <openssl/ssl.h>
#include <ws2tcpip.h>
#include <time.h>

#define CLIENT_READ(buf, len)   ((ssl) ? SSL_read(ssl, buf, len) : recv(client_fd, buf, len, 0))
#define CLIENT_WRITE(buf, len)  ((ssl) ? SSL_write(ssl, buf, len) : send(client_fd, buf, len, 0))

extern SSL_CTX *global_ssl_ctx;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 8192*2
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

static const char* extract_method(const char *request) {
    if (!request) return "GET";
    const char *space = strchr(request, ' ');
    if (!space) return "GET";
    static char method[16];
    size_t len = space - request;
    if (len >= sizeof(method)) len = sizeof(method) - 1;
    memcpy(method, request, len);
    method[len] = '\0';
    return method;
}

static int extract_path_query(const char *request, char *path_out, size_t path_size, char *query_out, size_t query_size) {
    if (!request || !path_out || !query_out || path_size == 0 || query_size == 0) return -1;
    
    path_out[0] = '\0';
    query_out[0] = '\0';

    const char *sp1 = strchr(request, ' ');
    if (!sp1) return -1;

    const char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) return -1;

    size_t uri_len = sp2 - (sp1 + 1);
    if (uri_len == 0) return -1;

    const char *qmark = memchr(sp1 + 1, '?', uri_len);
    if (qmark && qmark < sp2) {

        size_t path_len = qmark - (sp1 + 1);
        size_t query_len = sp2 - (qmark + 1);
        
        if (path_len > 0 && path_len < path_size) {
            memcpy(path_out, sp1 + 1, path_len);
            path_out[path_len] = '\0';
        } else if (path_len == 0) {
            strncpy(path_out, "/", path_size - 1);
            path_out[path_size - 1] = '\0';
        }
        
        if (query_len > 0 && query_len < query_size) {
            memcpy(query_out, qmark + 1, query_len);
            query_out[query_len] = '\0';
        }
    } else {

        if (uri_len < path_size) {
            memcpy(path_out, sp1 + 1, uri_len);
            path_out[uri_len] = '\0';
        }
    }
    
    if (path_out[0] == '\0') {
        strncpy(path_out, "/", path_size - 1);
        path_out[path_size - 1] = '\0';
    }
    
    return 0;
}

static int extract_accept_encoding(const char *request, char *out, size_t out_size) {
    if (!request || !out || out_size == 0) {
        if (out && out_size > 0) out[0] = '\0';
        return -1;
    }
    
    out[0] = '\0';
    
    const char *header_end = strstr(request, "\r\n\r\n");
    if (!header_end) return -1;
    
    const char *ae = strstr(request, "Accept-Encoding:");
    if (!ae) {
        ae = strstr(request, "accept-encoding:");
    }
    if (!ae || ae >= header_end) return 0; 

    ae += 15;
    while (*ae == ' ' || *ae == '\t') ae++;

    const char *line_end = strstr(ae, "\r\n");
    if (!line_end) line_end = header_end;
    
    size_t len = line_end - ae;
    if (len == 0) return 0;
    if (len >= out_size) len = out_size - 1;
    
    memcpy(out, ae, len);
    out[len] = '\0';

    while (len > 0 && (out[len - 1] == ' ' || out[len - 1] == '\t' || out[len - 1] == '\r')) {
        out[--len] = '\0';
    }
    
    return 0;
}

static void send_cached_response(SOCKET client_fd, SSL *ssl, cache_value_t *cached_value) {
    if (!cached_value) return;
    
    uint32_t now = (uint32_t)time(NULL);

    if (now >= cached_value->expires_at) {
        return;
    }
    
    uint32_t max_age = cached_value->expires_at - now;
    uint32_t age = max_age; 
    
    // Build HTTP response
    char response_header[4096];
    int n = snprintf(response_header, sizeof(response_header),
        "HTTP/1.1 %u %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Cache-Control: public, max-age=%u\r\n"
        "Age: %u\r\n"
        "X-Cache: HIT\r\n"
        "Connection: close\r\n"
        "\r\n",
        cached_value->status_code,
        cached_value->status_code == 200 ? "OK" : 
        cached_value->status_code == 404 ? "Not Found" :
        cached_value->status_code == 304 ? "Not Modified" : "OK",
        cached_value->content_type[0] ? cached_value->content_type : "text/plain",
        cached_value->body_len,
        max_age,
        age);
    
    if (n > 0 && n < (int)sizeof(response_header)) {
        send_all(client_fd, response_header, n, ssl);
        if (cached_value->body && cached_value->body_len > 0) {
            send_all(client_fd, (const char *)cached_value->body, cached_value->body_len, ssl);
        }
    }
}

int get_client_ip(SOCKET fd, char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    out[0] = '\0';

    struct sockaddr_storage ss; int slen = sizeof(ss);
    if (getpeername(fd, (struct sockaddr*)&ss, &slen) != 0) return -1;

    void *addr = NULL; int family = ((struct sockaddr*)&ss)->sa_family;
    if (family == AF_INET)      addr = &((struct sockaddr_in*)&ss)->sin_addr;
    else if (family == AF_INET6) addr = &((struct sockaddr_in6*)&ss)->sin6_addr;
    if (!addr) return -1;

    if (!inet_ntop(family, addr, out, (socklen_t)out_len)) return -1;
    return 0;
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

    set_tcp_nodelay(client_fd);

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
    
    // Trước khi kết nối backend: chạy filter-chain (nếu có)
    {
        FilterContext fctx;
        memset(&fctx, 0, sizeof(fctx));
        fctx.client_fd = client_fd;
        fctx.ssl = ssl;
        fctx.request = recv_buffer;
        fctx.request_len = total;
        fctx.route = rec;
        fctx.config = config;

        // Lấy IP client
        char cip[64] = {0};
        struct sockaddr_storage ss; int slen = sizeof(ss);
        if (getpeername(client_fd, (struct sockaddr*)&ss, &slen) == 0) {
            void *addr_ptr = NULL; int family = ((struct sockaddr*)&ss)->sa_family;
            if (family == AF_INET) {
                addr_ptr = &((struct sockaddr_in*)&ss)->sin_addr;
            } else if (family == AF_INET6) {
                addr_ptr = &((struct sockaddr_in6*)&ss)->sin6_addr;
            }
            if (addr_ptr) {
                inet_ntop(family, addr_ptr, cip, sizeof(cip));
            }
        }
        if (cip[0] == '\0') {
            strncpy(cip, "0.0.0.0", sizeof(cip)-1);
        }
        strncpy(fctx.client_ip, cip, sizeof(fctx.client_ip)-1);

        FilterResult fr = run_filters(&fctx);
        if (fr != FILTER_OK) {
            send_quick_error(client_fd, ssl, "429 Too Many Requests");
            goto cleanup;
        }
    }

    char cip[64];
    if (get_client_ip(client_fd, cip, sizeof(cip)) != 0) {
        strncpy(cip, "0.0.0.0", sizeof(cip)-1);
    }

    const char *method = extract_method(recv_buffer);
    char path[512] = {0};
    char query[512] = {0};
    char vary_header[256] = {0};
    extract_path_query(recv_buffer, path, sizeof(path), query, sizeof(query));
    extract_accept_encoding(recv_buffer, vary_header, sizeof(vary_header));

    int should_cache_response = 0;
    uint64_t cache_key_hash_val = 0;
    char cache_key_fingerprint[16] = {0};
    int was_cache_hit = 0;
    uint32_t final_status_code = 0; 
    uint64_t bytes_in = (uint64_t)total; 
    uint64_t bytes_out = 0;

    if (config->cache_enabled && strcmp(method, "GET") == 0) {
        cache_value_t *cached_value = NULL;
        cache_result_t cache_result = cache_get(method, ssl ? "https" : "http",
                                                host_from_request, path, 
                                                query[0] ? query : NULL, 
                                                vary_header[0] ? vary_header : NULL,
                                                &cached_value);
        
        if (cache_result == CACHE_RESULT_HIT && cached_value) {

            uint32_t now = (uint32_t)time(NULL);
            if (now < cached_value->expires_at) {
                was_cache_hit = 1;
                final_status_code = cached_value->status_code;
                bytes_out = (uint64_t)cached_value->body_len; 
                
                send_cached_response(client_fd, ssl, cached_value);

                {
                    char route[512];
                    size_t path_len = strlen(path);
                    if (path_len > 400) path_len = 400;
                    size_t query_len = query[0] ? strlen(query) : 0;
                    if (query_len > 100) query_len = 100;
                    
                    if (query[0] && query_len > 0) {
                        snprintf(route, sizeof(route), "%.*s?%.*s", 
                                (int)path_len, path, (int)query_len, query);
                    } else {
                        snprintf(route, sizeof(route), "%.*s", (int)path_len, path);
                    }
                    route[sizeof(route) - 1] = '\0';
                    request_tracker_record(route, method, final_status_code, host_from_request, bytes_in, bytes_out, was_cache_hit);
                }
                
                goto cleanup;
            }

        }

        char key_buf[2048];
        if (build_cache_key(method, ssl ? "https" : "http",
                           host_from_request, path,
                           query[0] ? query : NULL,
                           vary_header[0] ? vary_header : NULL,
                           key_buf, sizeof(key_buf)) == 0) {
            cache_key_hash(key_buf, &cache_key_hash_val, cache_key_fingerprint);
            should_cache_response = 1;  
        }
    }

    if (modify_request_headers(recv_buffer, send_buffer, sizeof(send_buffer), target_backend_host, target_backend_port, cip) != 0) {
        log_message("WARN", "Failed to modify HTTP headers, forwarding original request");
        strncpy(send_buffer, recv_buffer, sizeof(send_buffer) - 1);
        send_buffer[sizeof(send_buffer) - 1] = '\0';
    }
    int send_len = (int)strlen(send_buffer);

    if (connect_backend_auto(rec, target_backend_host, target_backend_port, &backend_fd, &backend_ssl) != 0) {
        log_message("ERROR", "Failed to connect to backend");
        send_quick_error(client_fd, ssl, "502 Bad Gateway");
        goto cleanup;
    }
    use_ssl = (backend_ssl != NULL);

    if (send_all(backend_fd, send_buffer, send_len, use_ssl ? backend_ssl : NULL) != 0) {
        log_message("ERROR", "Failed to send request headers to backend");
        goto cleanup;
    }

    frg_body_counter ctr;
    int initial_inbuf = 0;
    if (frg_body_counter_init(&ctr, 0, recv_buffer, total, &initial_inbuf) == 413) {
        send_quick_error(client_fd, ssl, "413 Payload Too Large");
        goto cleanup;
    }
    forward_already_read_body(recv_buffer, total, backend_fd, use_ssl ? backend_ssl : NULL);

    fd_set fds;
    int header_done = 0;
    int buffered = 0;
    char header_buf[HEADER_BUFFER_SIZE];

    long long content_length = -1;
    int is_chunked = 0;
    long long bytes_sent_body = 0;

    uint8_t *cache_body_buffer = NULL;
    size_t cache_body_size = 0;
    size_t cache_body_capacity = 0;
    uint32_t cache_status_code = 200;
    char cache_content_type[128] = {0};
    int cache_response_complete = 0;
    final_status_code = 200;

    while (1) {
        int n;
        if (use_ssl && backend_ssl && SSL_pending(backend_ssl) > 0) {
            n = SSL_read(backend_ssl, recv_buffer, sizeof(recv_buffer));
            if (n <= 0) break;
            goto process_backend_chunk;
        }

        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(backend_fd, &fds);
        int maxfd = (client_fd > backend_fd ? client_fd : backend_fd) + 1;

        int rv = select(maxfd, &fds, NULL, NULL, NULL);
        if (rv <= 0) break;

        if (FD_ISSET(client_fd, &fds)) {
            int ncli = (ssl ? SSL_read(ssl, recv_buffer, sizeof(recv_buffer)) : recv(client_fd, recv_buffer, sizeof(recv_buffer), 0));
            if (ncli <= 0) break;
            if (frg_body_counter_add(&ctr, (size_t)ncli) == 413) {
                send_quick_error(client_fd, ssl, "413 Payload Too Large");
                goto cleanup;
            }
            if (send_all(backend_fd, recv_buffer, ncli, use_ssl ? backend_ssl : NULL) != 0) break;
        }

        if (FD_ISSET(backend_fd, &fds)) {
            n = use_ssl ? SSL_read(backend_ssl, recv_buffer, sizeof(recv_buffer)) : recv(backend_fd, recv_buffer, sizeof(recv_buffer), 0);
            if (n <= 0) break;
        } else {
            continue;
        }

        process_backend_chunk:
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

                    char *status_line = header_buf;
                    if (strncmp(status_line, "HTTP/", 5) == 0) {
                        char *sp = strchr(status_line + 5, ' ');
                        if (sp) {
                            cache_status_code = (uint32_t)atoi(sp + 1);
                            final_status_code = cache_status_code;  // Update final status
                        }
                    }
                    
                    char *ct = strstr(header_buf, "Content-Type:");
                    if (!ct) ct = strstr(header_buf, "content-type:");
                    if (ct && ct < hdr_end) {
                        char *ct_val = ct + 13;
                        while (*ct_val == ' ' || *ct_val == '\t') ct_val++;
                        char *ct_end = strstr(ct_val, "\r\n");
                        if (!ct_end) ct_end = hdr_end;
                        size_t ct_len = ct_end - ct_val;
                        if (ct_len >= sizeof(cache_content_type)) ct_len = sizeof(cache_content_type) - 1;
                        memcpy(cache_content_type, ct_val, ct_len);
                        cache_content_type[ct_len] = '\0';
                    } else {
                        strncpy(cache_content_type, "text/plain", sizeof(cache_content_type) - 1);
                    }

                    if (should_cache_response && strcmp(method, "GET") == 0 && 
                        cache_status_code == 200 && !is_chunked && 
                        content_length >= 0 && content_length <= (long long)config->cache_max_object_bytes) {
                        cache_body_capacity = (size_t)content_length;
                        if (cache_body_capacity > 0) {
                            cache_body_buffer = (uint8_t *)malloc(cache_body_capacity);
                            if (!cache_body_buffer) {
                                should_cache_response = 0; 
                            }
                        }
                    } else {
                        should_cache_response = 0; 
                    }

                    char modified[HEADER_BUFFER_SIZE];
                    int new_len = modify_response_headers(header_buf, header_len, modified, sizeof(modified), target_backend_host, target_backend_port, config->listen_host, config->listen_port);
                    if (new_len > 0)
                        send_all(client_fd, modified, new_len, ssl);
                    else
                        send_all(client_fd, header_buf, header_len, ssl);

                    if (body_len > 0) {
                        send_all(client_fd, header_buf + header_len, body_len, ssl);
                        if (should_cache_response && cache_body_buffer && 
                            cache_body_size + body_len <= cache_body_capacity) {
                            memcpy(cache_body_buffer + cache_body_size, 
                                  header_buf + header_len, body_len);
                            cache_body_size += body_len;
                        }
                    }

                    header_done = 1;
                    buffered = 0;

                    bytes_sent_body = body_len;

                    if (content_length >= 0 && bytes_sent_body >= content_length) {
                        if (should_cache_response && cache_body_buffer) {
                            if (cache_body_size == cache_body_capacity) {
                                cache_response_complete = 1;
                            } else {
                                should_cache_response = 0;
                            }
                        } else {
                            cache_response_complete = 1;
                        }
                        break;
                    }
                }
            } else {
                if (send_all(client_fd, recv_buffer, n, ssl) != 0)
                    break;

                if (should_cache_response && cache_body_buffer && 
                    cache_body_size + n <= cache_body_capacity) {
                    memcpy(cache_body_buffer + cache_body_size, recv_buffer, n);
                    cache_body_size += n;
                }

                bytes_sent_body += n;
                bytes_out = (uint64_t)bytes_sent_body; 

                if (content_length >= 0) {
                    if (bytes_sent_body >= content_length) {

                        if (should_cache_response && cache_body_buffer) {
                            if (cache_body_size == cache_body_capacity) {
                                cache_response_complete = 1;
                            } else {

                                should_cache_response = 0;
                            }
                        } else {
                            cache_response_complete = 1;
                        }
                        break;
                    }
                } else if (is_chunked) {

                    if (strstr(recv_buffer, "\r\n0\r\n\r\n")) {
                        bytes_out = (uint64_t)bytes_sent_body; 
                        break;
                    }
                } else {

                    should_cache_response = 0;
                }
            }
    }

    if (should_cache_response && cache_body_buffer && cache_response_complete &&
        cache_body_size > 0 && cache_body_size <= config->cache_max_object_bytes &&
        cache_status_code == 200 && cache_body_size == cache_body_capacity) {  

        int should_cache = cache_check_admission(cache_key_hash_val, cache_key_fingerprint);

        static int cache_debug_count = 0;
        if (cache_debug_count < 10) {
            char debug_buf[512];
            size_t path_len = strlen(path);
            if (path_len > 100) path_len = 100;
            snprintf(debug_buf, sizeof(debug_buf), 
                    "[CACHE_DEBUG] path=%.*s, size=%llu/%llu, status=%u, should_cache=%d, admission=%d",
                    (int)path_len, path, 
                    (unsigned long long)cache_body_size, 
                    (unsigned long long)cache_body_capacity, 
                    cache_status_code, should_cache_response, should_cache);
            log_message("INFO", debug_buf);
            cache_debug_count++;
        }
        
        if (should_cache) {

            uint32_t ttl = config->cache_default_ttl_sec;

            if (cache_put(method, ssl ? "https" : "http",
                        host_from_request, path,
                        query[0] ? query : NULL,
                        vary_header[0] ? vary_header : NULL,
                        cache_status_code,
                        cache_body_buffer, (uint32_t)cache_body_size,
                        cache_content_type, ttl) == 0) {
                char log_buf[512];
                size_t path_len = strlen(path);
                size_t query_len = query[0] ? strlen(query) : 0;
                if (path_len > 150) path_len = 150;
                if (query_len > 50) query_len = 50;
                snprintf(log_buf, sizeof(log_buf), "[CACHE] Cached: %.*s%.*s (size=%llu)", 
                        (int)path_len, path, 
                        (int)query_len, query[0] ? query : "",
                        (unsigned long long)cache_body_size);
                log_message("INFO", log_buf);
            }
        } else if (should_cache_response && cache_debug_count < 10) {
            char debug_buf[512];
            size_t path_len = strlen(path);
            if (path_len > 150) path_len = 150;
            snprintf(debug_buf, sizeof(debug_buf), 
                    "[CACHE_DEBUG] NOT cached: path=%.*s, admission=%d (need 2nd hit in window)", 
                    (int)path_len, path, should_cache);
            log_message("INFO", debug_buf);
        }
    } else if (should_cache_response && strcmp(method, "GET") == 0) {
        static int cache_fail_count = 0;
        if (cache_fail_count < 10) {
            char debug_buf[512];
            size_t path_len = strlen(path);
            if (path_len > 150) path_len = 150;
            snprintf(debug_buf, sizeof(debug_buf), 
                    "[CACHE_DEBUG] Conditions failed: path=%.*s, status=%u, chunked=%d, size=%llu, complete=%d",
                    (int)path_len, path, 
                    cache_status_code, is_chunked, 
                    (unsigned long long)cache_body_size, 
                    cache_response_complete);
            log_message("INFO", debug_buf);
            cache_fail_count++;
        }
    }

    {

        char route[512];
        size_t path_len = strlen(path);
        if (path_len > 400) path_len = 400;
        size_t query_len = query[0] ? strlen(query) : 0;
        if (query_len > 100) query_len = 100;
        
        if (query[0] && query_len > 0) {
            snprintf(route, sizeof(route), "%.*s?%.*s", 
                    (int)path_len, path, (int)query_len, query);
        } else {
            snprintf(route, sizeof(route), "%.*s", (int)path_len, path);
        }
        route[sizeof(route) - 1] = '\0';  
        if (final_status_code == 0) {
            final_status_code = 200; 
        }
        if (!was_cache_hit && config->cache_enabled && bytes_out > 0) {
            if (strcmp(method, "GET") == 0) {
                cache_track_byte_miss(bytes_out);
            }
        }
        request_tracker_record(route, method, final_status_code, host_from_request, bytes_in, bytes_out, was_cache_hit);
    }

cleanup:

    if (cache_body_buffer) {
        free(cache_body_buffer);
        cache_body_buffer = NULL;
    }
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
