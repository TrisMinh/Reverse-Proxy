#include "acme_webroot.h"
#include <stdio.h>
#include <string.h>
#include <direct.h>

static int token_valid(const char *s) {
    if (!s || !*s) return 0;
    int n = 0;
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        unsigned c = *p;
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-')) return 0;
        if (++n > 256) return 0;
    }
    return 1;
}

static void send_text(SOCKET fd, const char *status, const char *body) {
    int bl = (int)(body ? strlen(body) : 0);
    char hdr[256];
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/plain\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        status, bl);
    send(fd, hdr, hl, 0);
    if (bl) send(fd, body, bl, 0);
}

static int send_file_plain(SOCKET fd, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n";
    send(fd, hdr, (int)strlen(hdr), 0);

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (send(fd, buf, (int)n, 0) <= 0) { fclose(f); return -1; }
    }
    fclose(f);
    return 0;
}

static int build_path(const char *webroot, const char *token, char *out, size_t outsz) {
    if (!webroot || !*webroot || !token || !*token || !out || !outsz) return -1;

    int n = snprintf(out, outsz, "%s", webroot);
    if (n <= 0 || (size_t)n >= outsz) return -1;

    if (out[n-1] != '\\' && out[n-1] != '/') {
        if ((size_t)n + 1 >= outsz) return -1;
        out[n++] = '\\';
        out[n] = '\0';
    }

    n += snprintf(out + n, outsz - n, ".well-known\\acme-challenge\\");
    if ((size_t)n >= outsz) return -1;

    n += snprintf(out + n, outsz - n, "%s", token);
    return ((size_t)n < outsz) ? 0 : -1;
}

int acme_try_handle_with_root(SOCKET client_fd, const char *method, const char *request_path, const char *webroot) {
    (void)method;

    const char *prefix = "/.well-known/acme-challenge/";
    if (!request_path) return 0;
    if (strncmp(request_path, prefix, (int)strlen(prefix)) != 0) return 0;

    const char *token = request_path + strlen(prefix);

    if (!token_valid(token) || strchr(token,'/') || strchr(token,'\\')) {
        send_text(client_fd, "400 Bad Request", "bad token\n");
        return 1;
    }

    const char *root = (webroot && *webroot) ? webroot : "D:\\proxy-data\\acme-webroot";

    char full[1024];
    if (build_path(root, token, full, sizeof(full)) != 0) {
        send_text(client_fd, "500 Internal Server Error", "");
        return 1;
    }

    if (send_file_plain(client_fd, full) == 0) return 1;

    send_text(client_fd, "404 Not Found", "");
    return 1;
}
