#include <string.h>
#include <ctype.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include "../include/filter_chain.h"
#include "../include/filter_request_guard.h"
#include "logger.h"

static int G_HDR_MAX = 128 * 1024;
static long long G_BODY_MAX = 1*1024*1024;

void frg_set_header_limit(int bytes) { G_HDR_MAX = bytes; }
void frg_set_body_limit(long long bytes) { G_BODY_MAX = bytes; }

static int find_hdr_end4(const char *s, size_t n, const char **hdr_end)
{
    if (!s || n < 4)
        return 0;
    for (size_t i = 3; i < n; i++)
    {
        if (s[i - 3] == '\r' && s[i - 2] == '\n' && s[i - 1] == '\r' && s[i] == '\n')
        {
            *hdr_end = s + i - 3;
            return 1;
        }
        if (s[i] == '\n' && s[i - 1] != '\r')
            return -1;
    }
    return 0;
}

static int ieq(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        unsigned char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z')
            x = (unsigned char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z')
            y = (unsigned char)(y - 'A' + 'a');
        if (x != y)
            return 0;
    }
    return 1;
}

int validate_http_request(const char *request)
{
    if (!request)
        return 400;
    size_t rlen = strlen(request);
    if (rlen < 10)
        return 400;

    const char *hdr_end = NULL;
    int fe = find_hdr_end4(request, rlen, &hdr_end);
    if (fe < 0)
        return 400;
    if (!fe)
        return 400;

    const char *sp1 = memchr(request, ' ', (size_t)(hdr_end - request));
    if (!sp1)
        return 400;
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(hdr_end - (sp1 + 1)));
    if (!sp2)
        return 400;
    if (sp2 + 8 > hdr_end || strncmp(sp2 + 1, "HTTP/1.", 7) != 0)
        return 400;

    size_t mlen = (size_t)(sp1 - request);
    if (!((mlen == 3 && memcmp(request, "GET", 3) == 0) ||
          (mlen == 4 && memcmp(request, "POST", 4) == 0) ||
          (mlen == 3 && memcmp(request, "PUT", 3) == 0) ||
          (mlen == 6 && memcmp(request, "DELETE", 6) == 0) ||
          (mlen == 4 && memcmp(request, "HEAD", 4) == 0) ||
          (mlen == 7 && memcmp(request, "OPTIONS", 7) == 0) ||
          (mlen == 5 && memcmp(request, "PATCH", 5) == 0)))
        return 400;

    const size_t MAX_TOTAL = (G_HDR_MAX > 0 ? (size_t)G_HDR_MAX : (size_t)(~0u >> 1));
    const int MAX_COUNT = 64;
    const size_t MAX_LINE = 16 * 1024;

    size_t header_total_bytes = (size_t)(hdr_end - request) + 4;
    if (G_HDR_MAX > 0 && header_total_bytes > MAX_TOTAL)
        return 431;

    int count = 0, cl_count = 0, te_present = 0, te_chunked_only = 1, host_present = 0;
    long long cl_value = -1;

    const char *line = memchr(request, '\n', (size_t)(hdr_end - request));
    if (!line)
        return 400;
    line += 1;

    while (line < hdr_end)
    {
        const char *eol = memchr(line, '\n', (size_t)(hdr_end - line));
        if (!eol)
            eol = hdr_end;
        size_t linelen = (size_t)(eol - line + 1);
        if (linelen - 1 > MAX_LINE)
            return 431;

        if (linelen > 2)
        {
            const char *colon = memchr(line, ':', (size_t)(eol - line));
            if (!colon)
                return 400;

            size_t name_len = (size_t)(colon - line);
            const char *val = colon + 1;
            while (val < eol && (*val == ' ' || *val == '\t'))
                val++;

            int is_cl = 0, is_te = 0, is_host = 0;
            if (name_len == 14 && ieq(line, "Content-Length", 14))
                is_cl = 1;
            else if (name_len == 17 && ieq(line, "Transfer-Encoding", 17))
                is_te = 1;
            else if (name_len == 4 && ieq(line, "Host", 4))
                is_host = 1;

            if (is_host)
            {
                host_present = 1;
            }
            else if (is_cl)
            {
                cl_count++;
                long long v = 0;
                int any = 0;
                const char *p = val;
                while (p < eol && *p >= '0' && *p <= '9')
                {
                    any = 1;
                    v = v * 10 + (*p - '0');
                    p++;
                }
                if (any)
                    cl_value = v;
            }
            else if (is_te)
            {
                te_present = 1;
                char buf[64];
                size_t n = (size_t)(eol - val);
                if (n >= sizeof(buf))
                    return 400;
                for (size_t i = 0; i < n; i++)
                {
                    char c = val[i];
                    if (c >= 'A' && c <= 'Z')
                        c = (char)(c - 'A' + 'a');
                    buf[i] = c;
                }
                buf[n] = 0;
                char *s = buf;
                while (*s == ' ' || *s == '\t')
                    s++;
                if (strchr(s, ',') || strcmp(s, "chunked") != 0)
                    te_chunked_only = 0;
            }
        }
        if (++count > MAX_COUNT)
            return 431;
        line = eol + 1;
    }

    if (!host_present)
        return 400;
    if (te_present && cl_count > 0)
        return 400;
    if (cl_count > 1)
        return 400;
    if (te_present && !te_chunked_only)
        return 400;
    if (G_BODY_MAX > 0 && cl_value >= 0 && cl_value > G_BODY_MAX)
        return 413;

    return 0;
}

static int frg_send_quick(SOCKET cfd, SSL *ssl, const char *status)
{
    char resp[160];
    int n = _snprintf(resp, sizeof(resp), "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
    if (n <= 0)
        return -1;
    int sent = 0;
    while (sent < n)
    {
        int w = ssl ? SSL_write(ssl, resp + sent, n - sent) : send(cfd, resp + sent, n - sent, 0);
        if (w <= 0)
            return -1;
        sent += w;
    }
    return 0;
}

FilterResult frg_chain_validate(FilterContext *ctx)
{
    if (!ctx || !ctx->request || ctx->request_len <= 0)
        return FILTER_OK;
    int st = validate_http_request(ctx->request);
    if (st == 0)
        return FILTER_OK;

    if (st == 431)
        frg_send_quick(ctx->client_fd, ctx->ssl, "431 Request Header Fields Too Large");
    else if (st == 413)
        frg_send_quick(ctx->client_fd, ctx->ssl, "413 Payload Too Large");
    else
        frg_send_quick(ctx->client_fd, ctx->ssl, "400 Bad Request");

    return FILTER_ERROR;
}

int frg_body_counter_init(frg_body_counter *c, long long limit_override, const char *req_buf, int total_read, int *initial_body_inbuf)
{
    if (!c)
        return 0;
    c->limit = (limit_override > 0 ? limit_override : G_BODY_MAX);
    c->seen = 0;

    int inbuf = 0;
    if (req_buf && total_read > 0)
    {
        const char *hdr_end = strstr(req_buf, "\r\n\r\n");
        if (hdr_end)
        {
            int hdr_len = (int)(hdr_end - req_buf) + 4;
            inbuf = total_read - hdr_len;
            if (inbuf < 0)
                inbuf = 0;
        }
    }

    if (initial_body_inbuf)
        *initial_body_inbuf = inbuf;

    if (c->limit > 0 && inbuf > 0)
    {
        long long after = c->seen + (long long)inbuf;
        if (after > c->limit)
            return 413;
        c->seen = after;
    }
    return 0;
}

int frg_body_counter_add(frg_body_counter *c, size_t nbytes)
{
    if (!c)
        return 0;
    if (c->limit > 0)
    {
        long long after = c->seen + (long long)nbytes;
        if (after > c->limit)
            return 413;
        c->seen = after;
    }
    return 0;
}
