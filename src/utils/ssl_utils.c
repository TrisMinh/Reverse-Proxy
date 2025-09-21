#include "../include/ssl_utils.h"
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

SSL_CTX* init_ssl_ctx() {
    //Nạp các thuật toán để dùng
    OpenSSL_add_ssl_algorithms();

    //Tạo môi trường ssl, cấu hình kết nối, TLS_client_method() kiểu là kết nối đến (bên đi kết nối)
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return NULL;
    }

    //SSL_VERIFY_PEER
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
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);

    // Note: inet_addr() chỉ nhận chuỗi IP. Nếu hostname thì sẽ fail: một bug tiềm năng. Xem xét

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return 0;
    }

    SSL *ssl = SSL_new(ctx);
    //gắn ssl vào socket tcp s
    SSL_set_fd(ssl, (int)s);

    int result = SSL_connect(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(s);

    return (result == 1) ? 1 : 0;
}
