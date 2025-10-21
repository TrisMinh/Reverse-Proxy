#include "../include/waf_sql.h"
#include "../include/logger.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#define LOG_IP_MAX 64
#define LOG_PATH_MAX 200

typedef struct
{
    const char *pat;
    int w;
} sig_t;

// https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/concepts/?utm_source=chatgpt.com
//    High = 25, Medium = 40 , Low = 60.
static const int OWASP_THRESHOLD_DEFAULT = 40;

// https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules?utm_source=chatgpt.com&tabs=drs21%2Cowasp32
static const sig_t PATS[] = {
    {"union select", 5},
    {"sleep(", 5},
    {"benchmark(", 5},
    {"into outfile", 5},
    {"load_file(", 5},
    {"information_schema", 4},
    {"or 1=1", 3},
    {"and 1=1", 2},
    {"--", 2},
    {"/*", 2},
    {"*/", 2},
    {"'", 2},
    {NULL, 0}
};

static void to_lower_ascii(char *s)
{
    while (*s)
    {
        if (*s >= 'A' && *s <= 'Z')
        {
            *s = (char)(*s - 'A' + 'a');
        }
        s++;
    }
}

static void collapse_spaces(char *s)
{
    char *w = s;
    int insp = 0;
    while (*s)
    {
        char c = *s++;
        if (c == '\r' || c == '\n' || c == '\t')
            c = ' ';
        if (c == ' ')
        {
            if (insp)
                continue;
            insp = 1;
            *w++ = ' ';
        }
        else
        {
            insp = 0;
            *w++ = c;
        }
    }
    *w = 0;
}

// Bỏ comment SQL:
// - -- ... (tới \n)
// - /* ... *\/
// - /*! ... *\/ (MySQL)
static void strip_sql_comments(char *s)
{
    char *r = s, *w = s;
    while (*r)
    {
        if (r[0] == '-' && r[1] == '-')
        {
            while (*r && *r != '\n')
                r++;
            continue;
        }
        if (r[0] == '/' && r[1] == '*')
        {
            int is_mysql = (r[2] == '!');
            r += is_mysql ? 3 : 2;
            while (r[0] && !(r[0] == '*' && r[1] == '/'))
                r++;
            if (r[0])
                r += 2;
            continue;
        }
        *w++ = *r++;
    }
    *w = 0;
}

/* Giải mã % một vòng: "%HH" -> byte.
   Ví dụ: "%2527" -> "%27" (double-encoding cho '\''; cần decode thêm vòng nữa mới ra '\'' ) */
static int pct_decode_once(const char *in, char *out, int cap)
{
    int oi = 0;
    for (int i = 0; in[i] && oi < cap - 1;)
    {
        unsigned char a = (unsigned char)in[i + 1], b = (unsigned char)in[i + 2];
        if (in[i] == '%' && isxdigit(a) && isxdigit(b))
        {
            int v = (isdigit(a) ? a - '0' : 10 + (tolower(a) - 'a'));
            v = (v << 4) + (isdigit(b) ? b - '0' : 10 + (tolower(b) - 'a'));
            out[oi++] = (char)v;
            i += 3;
        }
        else
        {
            out[oi++] = in[i++];
        }
    }
    out[oi] = 0;
    return oi;
}

static int score_buf(const char *buf)
{
    int sc = 0;
    for (const sig_t *p = PATS; p->pat; ++p)
    {
        if (strstr(buf, p->pat))
            sc += p->w;
    }
    return sc;
}

static int score_buf_padded(const char *buf)
{
    char pad[4100];
    size_t n = strlen(buf);
    if (n > sizeof(pad) - 3) n = sizeof(pad) - 3;
    pad[0] = ' ';
    memcpy(pad + 1, buf, n);
    pad[1 + n] = ' ';
    pad[2 + n] = 0;
    return score_buf(pad);
}

static void normalize_and_dual_score(const char *in, int *score_out)
{
    char a[4096];
    char b[4096];

    pct_decode_once(in, a, sizeof(a));
    to_lower_ascii(a);
    collapse_spaces(a);

    *score_out += score_buf_padded(a);

    memcpy(b, a, strlen(a) + 1);
    strip_sql_comments(b);
    *score_out += score_buf_padded(b);
}

static const char *find_body_ptr(const char *req)
{
    const char *p = strstr(req, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

static int extract_path_query(const char *req, char *out, int cap)
{
    const char *sp1 = strchr(req, ' ');
    const char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!sp1 || !sp2)
        return 0;
    int n = (int)(sp2 - (sp1 + 1));
    if (n <= 0)
        return 0;
    if (n >= cap)
        n = cap - 1;
    memcpy(out, sp1 + 1, n);
    out[n] = 0;
    return 1;
}

static int header_key_eq_ci(const char *p, size_t klen, const char *name)
{
    size_t nlen = strlen(name);
    if (klen != nlen)
        return 0;
    for (size_t i = 0; i < nlen; ++i)
    {
        unsigned char a = (unsigned char)p[i], b = (unsigned char)name[i];
        if (a >= 'A' && a <= 'Z')
            a = (unsigned char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
            b = (unsigned char)(b - 'A' + 'a');
        if (a != b)
            return 0;
    }
    return 1;
}

static const char *get_header_ci(const char *req, const char *name)
{
    const char *hdr = strstr(req, "\r\n");
    if (!hdr)
        return NULL;
    hdr += 2;
    const char *end = strstr(req, "\r\n\r\n");
    if (!end)
        return NULL;
    for (const char *p = hdr; p && p < end;)
    {
        const char *eol = strstr(p, "\r\n");
        if (!eol)
            break;
        const char *colon = memchr(p, ':', (size_t)(eol - p));
        if (colon)
        {
            size_t klen = (size_t)(colon - p);
            if (header_key_eq_ci(p, klen, name))
            {
                const char *val = colon + 1;
                while (val < eol && (*val == ' ' || *val == '\t'))
                    val++;
                return val;
            }
        }
        p = eol + 2;
    }
    return NULL;
}

FilterResult waf_sql_filter(FilterContext *ctx)
{
    if (!ctx || !ctx->request || ctx->request_len <= 0)
        return FILTER_OK;

    int threshold = OWASP_THRESHOLD_DEFAULT;
    char path[1024] = {0};
    if (extract_path_query(ctx->request, path, sizeof(path)))
    {
        if (strncmp(path, "/login", 6) == 0 || strncmp(path, "/search", 7) == 0 || strncmp(path, "/graphql", 8) == 0)
        {
            threshold = 25;
        }
        else if (strncmp(path, "/api/", 5) == 0)
        {
            threshold = 25;
        }
    }

    int score = 0;
    char tmp[4096];

    {
        char uri[2048] = {0};
        if (extract_path_query(ctx->request, uri, sizeof(uri)))
        {
            normalize_and_dual_score(uri, &score);
        }
    }

    // header
    {
        const char *ua = get_header_ci(ctx->request, "User-Agent");
        if (ua)
        {
            size_t n = strlen(ua);
            if (n >= sizeof(tmp))
                n = sizeof(tmp) - 1;
            memcpy(tmp, ua, n);
            tmp[n] = 0;
            normalize_and_dual_score(tmp, &score);
        }
        const char *rf = get_header_ci(ctx->request, "Referer");
        if (rf)
        {
            size_t n = strlen(rf);
            if (n >= sizeof(tmp))
                n = sizeof(tmp) - 1;
            memcpy(tmp, rf, n);
            tmp[n] = 0;
            normalize_and_dual_score(tmp, &score);
        }
    }

    // body
    {
        const char *body = find_body_ptr(ctx->request);
        if (body)
        {
            const char *end = ctx->request + ctx->request_len;
            size_t remain = (size_t)(end - body);
            if (remain > 0)
            {
                size_t n = remain < sizeof(tmp) - 1 ? remain : sizeof(tmp) - 1;
                memcpy(tmp, body, n);
                tmp[n] = 0;
                normalize_and_dual_score(tmp, &score);
            }
        }
    }

    if (score >= threshold)
    {
        char lb[512];
        const char *ip = (ctx->client_ip[0] ? ctx->client_ip : "-");
        const char *pp = (path[0] ? path : "/");

        snprintf(lb, sizeof(lb), "WAF_SQL block ip=%.48s score=%d path=%.128s", ip, score, pp);

        log_message("WARN", lb);
        return FILTER_DENY;
    }

    return FILTER_OK;
}
