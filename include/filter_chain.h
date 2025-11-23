#ifndef FILTER_CHAIN_H
#define FILTER_CHAIN_H

#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include "proxy_routes.h"
#include "config.h"

#define MAX_FILTERS 16  /* Số lượng bộ lọc (filter) tối đa có thể đăng ký */

/*
    Kết quả trả về của mỗi filter
    -----------------------------
    FILTER_OK     : Bộ lọc cho phép request đi tiếp
    FILTER_DENY   : Bộ lọc chặn request (không cho tiếp tục)
    FILTER_ERROR  : Xảy ra lỗi khi xử lý trong filter
*/
typedef enum {
    FILTER_OK = 0,
    FILTER_DENY = 1,
    FILTER_BLOCK = 2,
    FILTER_ERROR = -1
} FilterResult;

/*
    Cấu trúc ngữ cảnh truyền vào mỗi filter (FilterContext)
    --------------------------------------------------------
    - Chứa thông tin về client, request và route đang xử lý
    - Mỗi filter có thể đọc hoặc phân tích dữ liệu này
*/
typedef struct {
    SOCKET client_fd;              /* Socket của client */
    SSL *ssl;                      /* Con trỏ SSL (nếu dùng HTTPS) */
    const char *request;           /* Con trỏ trỏ tới vùng dữ liệu request */
    int request_len;               /* Độ dài request */
    char client_ip[64];            /* Địa chỉ IP của client (dạng chuỗi) */
    const ProxyRoute *route;       /* Thông tin route mà request đi qua */
    const Proxy_Config *config;    /* Cấu hình chung của proxy */
} FilterContext;

/* 
   Kiểu hàm cho mỗi filter 
   -----------------------
   - Mỗi filter nhận vào con trỏ FilterContext
   - Trả về giá trị FilterResult (FILTER_OK, FILTER_DENY, hoặc FILTER_ERROR)
*/
typedef FilterResult (*filter_fn_t)(FilterContext *ctx);

void init_filter_chain(void);
void shutdown_filter_chain(void);

/*
    Đăng ký một filter mới
    -----------------------
    - Mỗi filter là một hàm kiểu filter_fn_t
    - Trả về 0 nếu thành công, -1 nếu thất bại (ví dụ: đầy danh sách)
*/
int register_filter(filter_fn_t fn);
FilterResult run_filters(FilterContext *ctx);

#endif 
