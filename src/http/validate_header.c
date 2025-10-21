#include "../include/validate_header.h"
#include <stdio.h>
#include <string.h>

int validate_http_request(const char *request) {
    if (!request) return 400;
    size_t rlen = strlen(request);
    if (rlen < 10) return 400;

    // Tìm "\r\n\r\n" kết thúc header + cấm \r \n đơn lẻ
    const char *hdr_end = NULL;
    for (size_t i = 3; i < rlen; ++i) {
        if (request[i-3]=='\r' && request[i-2]=='\n' && request[i-1]=='\r' && request[i]=='\n') {
            hdr_end = request + i - 3;
            break;
        }
        if (request[i]=='\n' && request[i-1] != '\r') return 400;
    }
    if (!hdr_end) return 400;

    // METHOD HTTP/1.x
    const char *sp1 = memchr(request, ' ', (size_t)(hdr_end - request));
    if (!sp1) return 400;
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(hdr_end - (sp1 + 1)));
    if (!sp2) return 400;
    if (sp2 + 8 > hdr_end || strncmp(sp2 + 1, "HTTP/1.", 7) != 0) return 400;

    size_t mlen = (size_t)(sp1 - request);
    if (!((mlen==3 && memcmp(request,"GET",3)==0) ||
          (mlen==4 && memcmp(request,"POST",4)==0)||
          (mlen==3 && memcmp(request,"PUT",3)==0) ||
          (mlen==6 && memcmp(request,"DELETE",6)==0)||
          (mlen==4 && memcmp(request,"HEAD",4)==0) ||
          (mlen==7 && memcmp(request,"OPTIONS",7)==0)||
          (mlen==5 && memcmp(request,"PATCH",5)==0))) return 400;

    // GH tổng header/số header/độ dài dòng
    const size_t MAX_TOTAL = 64*1024;
    const int    MAX_COUNT = 64;
    const size_t MAX_LINE  = 8*1024;

    size_t total_hdr_bytes = (size_t)(hdr_end - request) + 2;
    if (total_hdr_bytes > MAX_TOTAL) return 431;

    int count=0, cl_count=0, te_present=0, te_chunked_only=1;

    const char *line = memchr(request, '\n', (size_t)(hdr_end - request));
    if (!line) return 400;
    line += 1;

    while (line < hdr_end) {
        const char *eol = memchr(line, '\n', (size_t)(hdr_end - line));
        if (!eol) eol = hdr_end;
        size_t linelen = (size_t)(eol - line + 1);
        if (linelen - 1 > MAX_LINE) return 431;

        if (linelen > 2) {
            const char *colon = memchr(line, ':', (size_t)(eol - line));
            if (!colon) return 400; // header không có ':'

            size_t name_len = (size_t)(colon - line);
            const char *val = colon + 1;
            while (val < eol && (*val==' ' || *val=='\t')) val++;

            int is_cl = 0, is_te = 0;
            if (name_len == 14) {
                const char *s = "Content-Length";
                is_cl = 1;
                for (size_t i=0;i<name_len;i++){
                    char a=(line[i]>='A'&&line[i]<='Z')? (char)(line[i]-'A'+'a') : line[i];
                    char b=(s[i]   >='A'&&s[i]   <='Z')? (char)(s[i]   -'A'+'a') : s[i];
                    if (a!=b) { is_cl=0; break; }
                }
            } else if (name_len == 17) {
                const char *s = "Transfer-Encoding";
                is_te = 1;
                for (size_t i=0;i<name_len;i++){
                    char a=(line[i]>='A'&&line[i]<='Z')? (char)(line[i]-'A'+'a') : line[i];
                    char b=(s[i]   >='A'&&s[i]   <='Z')? (char)(s[i]   -'A'+'a') : s[i];
                    if (a!=b) { is_te=0; break; }
                }
            }

            if (is_cl) {
                cl_count++;
            } else if (is_te) {
                te_present = 1;
                char buf[64];
                size_t n = (size_t)(eol - val);
                if (n >= sizeof(buf)) return 400;
                for (size_t i=0;i<n;i++){
                    char c = val[i];
                    if (c>='A' && c<='Z') c = (char)(c - 'A' + 'a');
                    buf[i] = c;
                }
                buf[n]=0;
                char *s = buf; while (*s==' ' || *s=='\t') s++;
                if (strchr(s, ',') || strcmp(s, "chunked") != 0) te_chunked_only = 0;
            }
        }
        if (++count > MAX_COUNT) return 431;
        line = eol + 1;
    }

    if (te_present && cl_count > 0) return 400;
    if (cl_count > 1)               return 400;
    if (te_present && !te_chunked_only) return 400;

    return 0; // OK
}
