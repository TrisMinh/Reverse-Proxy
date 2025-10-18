#include "../include/ssl_utils.h"
#include "../include/config.h"
#include "../include/logger.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

static void logmsgf_local(const char *level, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_message(level, buf);
}

SSL_CTX* init_ssl_ctx() {
    // Nạp các thuật toán để dùng
    OpenSSL_add_ssl_algorithms();

    // Tạo môi trường ssl, cấu hình kết nối, TLS_client_method() kiểu là kết nối đến (bên đi kết nối)
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return NULL;
    }

    // SSL_VERIFY_PEER (hiện để NONE để giữ hành vi cũ; nếu bật verify cần load CA + set hostname)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // if (SSL_CTX_load_verify_locations(ctx, "", NULL) != 1) {
    //     ERR_print_errors_fp(stderr);
    //     SSL_CTX_free(ctx);
    //     return NULL;
    // }

    return ctx;
}

void cleanup_ssl_ctx(SSL_CTX *ctx) {
    if (ctx) SSL_CTX_free(ctx);
    EVP_cleanup();
}

// Kiểm tra backend có hỗ trợ HTTPS hay không
int test_https_handshake(SSL_CTX *ctx, const char *host, int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return 0;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);

    int result = SSL_connect(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(s);

    return (result == 1) ? 1 : 0;
}

typedef struct CertCache {
    char domain[256];
    SSL_CTX *ctx;
    struct CertCache *next;
} CertCache;

static CertCache *cert_list = NULL;
static SSL_CTX *default_ctx = NULL;

static SSL_CTX *create_ctx_from_cert(const char *domain) {
    const Proxy_Config *cfg = get_config();
    const char *certdir = (cfg && cfg->cert_dir[0]) ? cfg->cert_dir : "../cert";

    const char *crt_path = NULL;
    const char *key_path = NULL;
    FILE *f;

    char path_crt[1024];
    char path_key[1024];
    char path_chain[1024];
    char path_chain_only[1024];

    snprintf(path_crt, sizeof(path_crt), "%s/%s/%s-crt.pem", certdir, domain, domain);
    snprintf(path_key, sizeof(path_key), "%s/%s/%s-key.pem", certdir, domain, domain);
    snprintf(path_chain, sizeof(path_chain), "%s/%s/%s-chain.pem", certdir, domain, domain);
    snprintf(path_chain_only, sizeof(path_chain_only), "%s/%s/%s-chain-only.pem", certdir, domain, domain);

    f = fopen(path_crt, "r");
    if (f) { fclose(f);
        f = fopen(path_key, "r");
        if (f) { fclose(f);
            crt_path = path_crt;
            key_path = path_key;
        }
    }

    if (!crt_path) {
        f = fopen(path_chain, "r");
        if (f) { fclose(f);
            f = fopen(path_key, "r");
            if (f) { fclose(f);
                crt_path = path_chain;
                key_path = path_key;
            }
        }
    }

    if (!crt_path) {
        f = fopen(path_chain_only, "r");
        if (f) { fclose(f);
            f = fopen(path_key, "r");
            if (f) { fclose(f);
                crt_path = path_chain_only;
                key_path = path_key;
            }
        }
    }

    if (!crt_path || !key_path) {
        logmsgf_local("WARN", "No valid certificate pair found for %s - using default", domain);
        return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        logmsgf_local("ERROR", "Failed to create SSL_CTX for %s", domain);
        return NULL;
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, crt_path, SSL_FILETYPE_PEM) <= 0) {
        logmsgf_local("ERROR", "Invalid certificate file: %s", crt_path);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        logmsgf_local("ERROR", "Invalid private key file: %s", key_path);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        logmsgf_local("ERROR", "Certificate and key do not match for %s", domain);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static SSL_CTX *get_ctx_for_domain(const char *domain) {
    for (CertCache *c = cert_list; c; c = c->next)
        if (strcmp(c->domain, domain) == 0)
            return c->ctx;

    SSL_CTX *ctx = create_ctx_from_cert(domain);
    if (!ctx) return default_ctx;

    CertCache *node = (CertCache*)malloc(sizeof(CertCache));
    strcpy(node->domain, domain);
    node->ctx = ctx;
    node->next = cert_list;
    cert_list = node;

    return ctx;
}

static int sni_callback(SSL *ssl, int *ad, void *arg) {
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername) return SSL_TLSEXT_ERR_OK;

    SSL_CTX *ctx = get_ctx_for_domain(servername);
    if (ctx) {
        SSL_set_SSL_CTX(ssl, ctx);
        // logmsgf_local("INFO", "Using cert for %s", servername);
        return SSL_TLSEXT_ERR_OK;
    } else {
        logmsgf_local("ERROR", "No valid cert for %s ", servername);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

SSL_CTX* init_ssl_server_ctx() {
    const Proxy_Config *cfg = get_config();
    const char *certdir = (cfg && cfg->cert_dir[0]) ? cfg->cert_dir : "../cert";

    char default_crt[1024], default_key[1024];
    snprintf(default_crt, sizeof(default_crt), "%s/default.crt", certdir);
    snprintf(default_key, sizeof(default_key), "%s/default.key", certdir);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log_message("FATAL", "Cannot create default SSL_CTX");
        return NULL;
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, default_crt, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, default_key, SSL_FILETYPE_PEM) <= 0) {
        log_message("FATAL", "Missing default.crt / default.key : cannot start HTTPS");
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_tlsext_servername_callback(ctx, sni_callback);
    default_ctx = ctx;

    log_message("INFO", "SSL server context initialized (default cert)");
    return ctx;
}

void free_ssl_cert_cache() {
    CertCache *c = cert_list;
    while (c) {
        CertCache *n = c->next;
        SSL_CTX_free(c->ctx);
        free(c);
        c = n;
    }
}
