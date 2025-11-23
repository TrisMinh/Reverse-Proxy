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

typedef struct CertNode {
    char domain[256];
    SSL_CTX *ctx;
    struct CertNode *next;
} CertNode;

#define CERT_HT_SIZE 128
static CertNode* cert_ht[CERT_HT_SIZE] = {0};
static SSL_CTX *default_ctx = NULL;

static unsigned cert_hash_ci(const char *s) {
    unsigned long h = 5381;
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        unsigned c = *p;
        if (c >= 'A' && c <= 'Z') c = (unsigned)(c - 'A' + 'a');
        h = ((h << 5) + h) + c;
    }
    return (unsigned)h & (CERT_HT_SIZE - 1);
}

static SSL_CTX* cert_cache_get(const char *domain) {
    unsigned idx = cert_hash_ci(domain);
    for (CertNode *n = cert_ht[idx]; n; n = n->next) {
        if (_stricmp(n->domain, domain) == 0) return n->ctx;
    }
    return NULL;
}

static void cert_cache_put(const char *domain, SSL_CTX *ctx) {
    unsigned idx = cert_hash_ci(domain);
    for (CertNode *n = cert_ht[idx]; n; n = n->next) {
        if (_stricmp(n->domain, domain) == 0) { n->ctx = ctx; return; }
    }
    CertNode *node = (CertNode*)malloc(sizeof(CertNode));
    _snprintf(node->domain, sizeof(node->domain), "%s", domain);
    node->domain[sizeof(node->domain)-1] = 0;
    node->ctx = ctx;
    node->next = cert_ht[idx];
    cert_ht[idx] = node;
}

static void str_to_lower_inplace(char *s) {
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') *s = (char)(c - 'A' + 'a');
    }
}

static int strip_www(const char *in, char *out, size_t cap) {
    if (!in || !out || cap == 0) return 0;
    const char *p = in;
    if ((p[0]|32) == 'w' && (p[1]|32) == 'w' && (p[2]|32) == 'w' && p[3] == '.') {
        p += 4;
    }
    size_t n = strlen(p);
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n);
    out[n] = 0;
    return 1;
}

static SSL_CTX *create_ctx_from_cert_one(const char *domain) {
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
            crt_path = path_crt; key_path = path_key;
        }
    }
    if (!crt_path) {
        f = fopen(path_chain, "r");
        if (f) { fclose(f);
            f = fopen(path_key, "r");
            if (f) { fclose(f);
                crt_path = path_chain; key_path = path_key;
            }
        }
    }
    if (!crt_path) {
        f = fopen(path_chain_only, "r");
        if (f) { fclose(f);
            f = fopen(path_key, "r");
            if (f) { fclose(f);
                crt_path = path_chain_only; key_path = path_key;
            }
        }
    }

    if (!crt_path || !key_path) {
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

static SSL_CTX *create_ctx_from_cert(const char *domain) {
    SSL_CTX *ctx = create_ctx_from_cert_one(domain);
    if (ctx) return ctx;

    char bare[256];
    if (strip_www(domain, bare, sizeof(bare)) && _stricmp(bare, domain) != 0) {
        ctx = create_ctx_from_cert_one(bare);
        if (ctx) return ctx;
    }

    return NULL;
}

static SSL_CTX *get_ctx_for_domain(const char *domain) {
    SSL_CTX *ctx = cert_cache_get(domain);
    if (ctx) return ctx;

    ctx = create_ctx_from_cert(domain);
    if (ctx) {
        cert_cache_put(domain, ctx);

        char bare[256];
        if (strip_www(domain, bare, sizeof(bare)) && _stricmp(bare, domain) != 0) {
            cert_cache_put(bare, ctx);
            logmsgf_local("INFO", "SNI %s -> using cert for %s", domain, bare);
        }
        return ctx;
    }

    char bare2[256];
    if (strip_www(domain, bare2, sizeof(bare2)) && _stricmp(bare2, domain) != 0) {
        logmsgf_local("WARN", "No valid certificate pair for %s (also tried %s)", domain, bare2);
    } else {
        logmsgf_local("WARN", "No valid certificate pair for %s - using default", domain);
    }
    return default_ctx;
}

static int sni_callback(SSL *ssl, int *ad, void *arg) {
    (void)ad; (void)arg;
    const char *servername_raw = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername_raw) return SSL_TLSEXT_ERR_OK;

    char sni[256];
    _snprintf(sni, sizeof(sni), "%s", servername_raw);
    sni[sizeof(sni)-1] = 0;
    str_to_lower_inplace(sni);

    SSL_CTX *ctx = get_ctx_for_domain(sni);
    if (ctx) {
        SSL_set_SSL_CTX(ssl, ctx);
        return SSL_TLSEXT_ERR_OK;
    } else {
        // logmsgf_local("WARN", "No matching cert for SNI=%s (tried exact and no-www), using default", sni);
        return SSL_TLSEXT_ERR_OK;
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
    SSL_CTX **uniq = NULL;
    size_t ucap = 0, usize = 0;

    for (int i = 0; i < CERT_HT_SIZE; ++i) {
        for (CertNode *n = cert_ht[i]; n; n = n->next) {
            SSL_CTX *p = n->ctx;
            if (!p) continue;
            int seen = 0;
            for (size_t k = 0; k < usize; ++k) {
                if (uniq[k] == p) { seen = 1; break; }
            }
            if (!seen) {
                if (usize == ucap) {
                    size_t ncap = (ucap ? ucap * 2 : 16);
                    SSL_CTX **tmp = (SSL_CTX**)realloc(uniq, ncap * sizeof(SSL_CTX*));
                    if (!tmp) {
                        SSL_CTX_free(p);
                        n->ctx = NULL;
                        continue;
                    }
                    uniq = tmp; ucap = ncap;
                }
                uniq[usize++] = p;
            }
        }
    }

    for (size_t i = 0; i < usize; ++i) {
        SSL_CTX_free(uniq[i]);
    }
    free(uniq);

    for (int i = 0; i < CERT_HT_SIZE; ++i) {
        CertNode *n = cert_ht[i];
        while (n) {
            CertNode *next = n->next;
            free(n);
            n = next;
        }
        cert_ht[i] = NULL;
    }
}
