#include "captcha_filter.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "cJSON.h"
#include "filter_chain.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <time.h>
#include "../include/clearance_token.h"

static char *CAPTCHA_CENTER_URL = "http://ngosing:5500/solve.html";
static char *CAPTCHA_SECRET_KEY = "qwerasdzxcrtyfghvbnuiojklnm01923456746839";
static char *RECAPTCHA_SECRET_KEY = "6Ldi7PgrAAAAAHIqoT9bzydpM-ZFJGDPj09zSmZ2";
static char *CAPTCHA_CALLBACK_PATH = "/__captcha/callback";
static int CAPTCHA_STATE_TTL_SEC = 300;
static int CAPTCHA_PASS_TTL_SEC = 1800;

void set_captcha_config(const char *center_url, const char *secret_key, const char *recaptcha_key,
                        const char *callback_path, int state_ttl, int pass_ttl)
{
    if (center_url)    CAPTCHA_CENTER_URL    = strdup(center_url);
    if (secret_key)    CAPTCHA_SECRET_KEY    = strdup(secret_key);
    if (recaptcha_key) RECAPTCHA_SECRET_KEY  = strdup(recaptcha_key);
    if (callback_path) CAPTCHA_CALLBACK_PATH = strdup(callback_path);
    if (state_ttl > 0) CAPTCHA_STATE_TTL_SEC = state_ttl;
    if (pass_ttl  > 0) CAPTCHA_PASS_TTL_SEC  = pass_ttl;
}

static int send_raw(FilterContext *ctx, const char *data, size_t len) {
    if (!ctx || !data || len == 0)
        return -1;
    size_t sent = 0;
    while (sent < len) {
        int n = ctx->ssl ? SSL_write(ctx->ssl, data + sent, (int)(len - sent)) : send(ctx->client_fd, data + sent, (int)(len - sent), 0);
        if (n <= 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}

static void send_http_response(FilterContext *ctx, int status_code, const char *content_type, const char *body)
{
    if (!content_type)
        content_type = "text/plain";
    if (!body)
        body = "";
    char head[512];
    int hl = snprintf(head, sizeof(head),
                      "HTTP/1.1 %d %s\r\n"
                      "Content-Type: %s; charset=utf-8\r\n"
                      "Content-Length: %lu\r\n"
                      "Connection: close\r\n\r\n",
                      status_code, (status_code == 200 ? "OK" : status_code == 302 ? "Found" : status_code == 400   ? "Bad Request" : status_code == 403   ? "Forbidden": "Internal Server Error"),
                      content_type,
                      (unsigned long)strlen(body));
    if (hl > 0) {
        send_raw(ctx, head, (size_t)hl);
        send_raw(ctx, body, strlen(body));
    }
}

static const char* get_header_ci(const char *req, const char *name, const char **val_end_out) {
    const char *p = strstr(req, "\r\n");
    if (!p) return NULL;
    p += 2;
    const char *hdr_end = strstr(p, "\r\n\r\n");
    if (!hdr_end) return NULL;

    size_t nlen = strlen(name);

    while (p < hdr_end) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;

        const char *colon = memchr(p, ':', (size_t)(eol - p));
        if (!colon) { p = eol + 2; continue; }

        size_t klen = (size_t)(colon - p);
        if (klen == nlen && _strnicmp(p, name, (unsigned)nlen) == 0) {
            const char *val = colon + 1;
            while (val < eol && (*val == ' ' || *val == '\t')) val++; 
            if (val_end_out) *val_end_out = eol;
            return val;
        }
        p = eol + 2;
    }
    return NULL;
}


static const char *get_cookie(const char *raw_request, const char *name) {
    static char out[256];
    const char *end = NULL;
    const char *ck = get_header_ci(raw_request, "Cookie", &end);
    if (!ck || !end) return NULL;
    size_t nlen = strlen(name);
    const char *p = ck;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == ';' || *p == ',')) p++;
        if (p >= end) break;
        const char *eq = memchr(p, '=', (size_t)(end - p));
        if (!eq) break;
        size_t klen = (size_t)(eq - p);
        const char *val = eq + 1;
        const char *stop = val;
        while (stop < end && *stop != ';' && *stop != ',') stop++;
        if (klen == nlen && memcmp(p, name, nlen) == 0) {
            size_t vlen = (size_t)(stop - val);
            if (vlen >= sizeof(out)) vlen = sizeof(out) - 1;
            memcpy(out, val, vlen);
            out[vlen] = '\0';
            return out;
        }
        p = (stop < end) ? (stop + 1) : end;
    }
    return NULL;
}

static const char *get_param(const char *req, const char *name) {
    static char out[8192];
    const char *sp1 = strchr(req, ' '), *sp2 = sp1 ? strchr(sp1+1, ' ') : NULL;
    if (!sp1 || !sp2) return NULL;
    const char *q = memchr(sp1+1, '?', (size_t)(sp2 - (sp1+1)));
    if (!q) return NULL;
    q++;
    size_t nlen = strlen(name);
    const char *p = q, *qend = sp2;
    while (p < qend) {
        const char *eq = memchr(p, '=', (size_t)(qend - p)); if (!eq) break;
        const char *amp = memchr(eq+1, '&', (size_t)(qend - (eq+1)));
        const char *stop = amp ? amp : qend;
        if ((size_t)(eq - p) == nlen && memcmp(p, name, nlen) == 0) {
            size_t vlen = (size_t)(stop - (eq+1));
            if (vlen >= sizeof(out)) vlen = sizeof(out)-1;
            memcpy(out, eq+1, vlen); out[vlen] = '\0';
            return out;
        }
        p = stop + 1;
    }
    return NULL;
}

static int suspect_ip(const char *ip) {
    return 1;
}

struct buffer {
    char *data;
    size_t size;
};

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct buffer *mem = (struct buffer *)userp;
    char *p = (char *)realloc(mem->data, mem->size + realsize + 1);
    if (!p) return 0;
    mem->data = p;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

static int verify_recaptcha(const char *secret, const char *token, const char *client_ip) {
    if (!secret || !*secret || !token || !*token) return 0;
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    struct buffer chunk = {0};
    char post[8192];
    char *esc_secret = curl_easy_escape(curl, secret, 0);
    char *esc_token = curl_easy_escape(curl, token, 0);
    snprintf(post, sizeof(post), "secret=%s&response=%s", esc_secret, esc_token);
    curl_free(esc_secret);
    curl_free(esc_token);
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com/recaptcha/api/siteverify");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, "../resources/certs/ca-bundle.crt");
    int ok = 0;
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK && chunk.data && chunk.size > 0) {
        cJSON *root = cJSON_Parse(chunk.data);
        if (root) {
            cJSON *success = cJSON_GetObjectItem(root, "success");
            if (cJSON_IsBool(success) && cJSON_IsTrue(success))
                ok = 1;
            cJSON_Delete(root);
        }
    }
    curl_easy_cleanup(curl);
    free(chunk.data);
    return ok;
}

static void urlencode(const char *in, char *out, size_t outsz) {
    static const char safe[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 4 < outsz; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (strchr(safe, c)) out[j++] = c;
        else if (c == ' ') { out[j++] = '%'; out[j++] = '2'; out[j++] = '0'; }
        else {
            static const char *H = "0123456789ABCDEF";
            out[j++] = '%'; out[j++] = H[(c >> 4) & 0xF]; out[j++] = H[c & 0xF];
        }
    }
    if (j < outsz) out[j] = 0;
}

static size_t urldecode(const char *in, char *out, size_t outsz) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < outsz; ++i) {
        if (in[i] == '%' && in[i+1] && in[i+2]) {
            int hi = in[i+1], lo = in[i+2];
            int v  = (hi >= 'A' ? (hi & ~0x20) - 'A' + 10 : hi - '0');
            int w  = (lo >= 'A' ? (lo & ~0x20) - 'A' + 10 : lo - '0');
            if ((unsigned)v < 16 && (unsigned)w < 16) { out[j++] = (char)((v<<4)|w); i+=2; continue; }
        }
        out[j++] = in[i];
    }
    if (j < outsz) out[j] = '\0';
    return j;
}

static void build_original_url(FilterContext *ctx, char *dst, size_t dstsz) {
    const char *host_end = NULL;
    const char *host = get_header_ci(ctx->request, "Host", &host_end);
    if (!host) host = "";
    const char *sp1 = strchr(ctx->request, ' ');
    const char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    const char *path = (sp1 && sp2) ? sp1 + 1 : "/";
    size_t plen = (sp1 && sp2) ? (size_t)(sp2 - (sp1 + 1)) : 1;
    const char *scheme = ctx->ssl ? "https" : "http";
    snprintf(dst, dstsz, "%s://%.*s%.*s", scheme, host_end ? (int)(host_end - host) : (int)strlen(host), host, (int)plen, path);
}

static int is_safe_return_url(FilterContext *ctx, const char *url) {
    const char *host_end = NULL;
    const char *host = get_header_ci(ctx->request, "Host", &host_end);
    if (!host) return 0;
    char host_now[256] = {0};
    snprintf(host_now, sizeof(host_now), "%.*s", host_end ? (int)(host_end - host) : (int)strlen(host), host);
    const char *p = strstr(url, "://");
    if (!p) return 0;
    p += 3;
    const char *slash = strchr(p, '/');
    size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
    return (strlen(host_now) == hlen && _strnicmp(host_now, p, hlen) == 0);
}

static void redirect_to_captcha_center(FilterContext *ctx) {
    const char *center = CAPTCHA_CENTER_URL;
    char orig[2048];
    build_original_url(ctx, orig, sizeof(orig));
    char ts[32];
    snprintf(ts, sizeof(ts), "%u", (unsigned)time(NULL));
    char material[2300];
    snprintf(material, sizeof(material), "%s|%s", orig, ts);
    const char *secret = CAPTCHA_SECRET_KEY;
    unsigned char mac[32];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), secret, (int)strlen(secret), (unsigned char *)material, (int)strlen(material), mac, &mac_len);
    char mac_hex[65];
    hexify(mac, mac_len, mac_hex, sizeof(mac_hex));
    char orig_enc[4096];
    urlencode(orig, orig_enc, sizeof(orig_enc));
    char state[4600];
    snprintf(state, sizeof(state), "%s.%s.%s", mac_hex, orig_enc, ts);
    char state_enc[6000];
    urlencode(state, state_enc, sizeof(state_enc));
    char loc[8192];
    snprintf(loc, sizeof(loc), "%s?state=%s", center, state_enc);
    char head[1024];
    int hl = snprintf(head, sizeof(head),
                      "HTTP/1.1 302 Found\r\n"
                      "Location: %s\r\n"
                      "Cache-Control: no-store\r\n"
                      "Content-Length: 0\r\n"
                      "Connection: close\r\n\r\n",
                      loc);
    send_raw(ctx, head, (size_t)hl);
}

static void handle_captcha_callback(FilterContext *ctx) {
    const char *state_raw = get_param(ctx->request, "state");
    char state[8192] = {0};
    if (state_raw) strncpy(state, state_raw, sizeof(state) - 1);

    const char *token_raw = get_param(ctx->request, "token");
    char token_q[8192] = {0};
    if (token_raw) strncpy(token_q, token_raw, sizeof(token_q) - 1);

    if (state[0] == '\0' || token_q[0] == '\0') {
        send_http_response(ctx, 400, "text/html", "<h2>Bad Request</h2>");
        return;
    }

    const char *dot1 = strchr(state, '.');
    const char *dot2 = strrchr(state, '.');
    if (!dot1 || !dot2) {
        send_http_response(ctx, 403, "text/html", "<h2>Forbidden</h2>");
        return;
    }
    char mac_hex[65] = {0};
    snprintf(mac_hex, sizeof(mac_hex), "%.*s", (int)(dot1 - state), state);
    char orig_enc[4096] = {0};
    snprintf(orig_enc, sizeof(orig_enc), "%.*s", (int)(dot2 - (dot1 + 1)), dot1 + 1);
    const char *ts_str = dot2 + 1;
    char orig[4096] = {0};
    urldecode(orig_enc, orig, sizeof(orig));
    unsigned now = (unsigned)time(NULL);
    unsigned ts  = (unsigned)strtoul(ts_str, NULL, 10);
    unsigned ttl = (unsigned)CAPTCHA_STATE_TTL_SEC;
    if (now < ts || now - ts > ttl) {
        send_http_response(ctx, 403, "text/html", "<h2>State expired</h2>");
        return;
    }

    const char *secret = CAPTCHA_SECRET_KEY;
    char material[4600];
    snprintf(material, sizeof(material), "%s|%s", orig, ts_str);
    unsigned char mac[32]; unsigned int mac_len = 0;
    HMAC(EVP_sha256(), secret, (int)strlen(secret), (unsigned char *)material, (int)strlen(material), mac, &mac_len);
    char mac_calc_hex[65] = {0};
    hexify(mac, mac_len, mac_calc_hex, sizeof(mac_calc_hex));
    if (_stricmp(mac_hex, mac_calc_hex) != 0) {
        send_http_response(ctx, 403, "text/html", "<h2>Bad state</h2>");
        return;
    }
    char token[8192] = {0};
    urldecode(token_q, token, sizeof(token));

    const char *rc_secret = RECAPTCHA_SECRET_KEY;
    if (!verify_recaptcha(rc_secret, token, ctx->client_ip)) {
        send_http_response(ctx, 403, "text/html", "<h2>Verification failed</h2>");
        return;
    }

    if (!is_safe_return_url(ctx, orig)) {
        send_http_response(ctx, 403, "text/html", "<h2>Forbidden return</h2>");
        return;
    }

    const char *ua = get_header_ci(ctx->request, "User-Agent", NULL);
    char *token_ck = generate_clearance_token(ctx->client_ip, ua, CAPTCHA_SECRET_KEY);
    if (!token_ck) {
        send_http_response(ctx, 500, "text/html", "<h2>Server Error</h2>");
        return;
    }
    char head[2048];
    int hl = snprintf(head, sizeof(head),
                      "HTTP/1.1 302 Found\r\n"
                      "Set-Cookie: tk_clearance=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax\r\n"
                      "Location: %s\r\n"
                      "Cache-Control: no-store\r\n"
                      "Content-Length: 0\r\n"
                      "Connection: close\r\n\r\n",
                      token_ck, CAPTCHA_PASS_TTL_SEC, orig);
    send_raw(ctx, head, (size_t)hl);
    free(token_ck);
}

FilterResult captcha_filter(FilterContext *ctx) {
    const char *sp1 = strchr(ctx->request, ' ');
    const char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;

    if (sp1 && sp2) {
        int n = (int)(sp2 - (sp1 + 1));
        if (n < 0) n = 0;
        char pathbuf[1024];
        int m = n < (int)sizeof(pathbuf) - 1 ? n : (int)sizeof(pathbuf) - 1;
        memcpy(pathbuf, sp1 + 1, m);
        pathbuf[m] = 0;
        if (strstr(pathbuf, "/solve.html")) return FILTER_OK;
        if (strstr(pathbuf, CAPTCHA_CALLBACK_PATH)) { handle_captcha_callback(ctx); return FILTER_OK; }
    }

    const char *cookie = get_cookie(ctx->request, "tk_clearance");
    if (cookie && cookie[0]) {
        const char *ua = get_header_ci(ctx->request, "User-Agent", NULL);
        if (verify_clearance_token(cookie, ctx->client_ip, ua, CAPTCHA_SECRET_KEY, CAPTCHA_PASS_TTL_SEC)) {
            return FILTER_OK;
        }
    }

    if (suspect_ip(ctx->client_ip)) {
        redirect_to_captcha_center(ctx);
        return FILTER_DENY;
    }
    return FILTER_OK;
}
