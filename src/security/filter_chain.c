#include <stddef.h>
#include "../include/filter_chain.h"

static filter_fn_t g_filters[MAX_FILTERS];     // Mảng lưu các filter function
static int g_filter_count = 0;                 // Số lượng filter hiện có
static CRITICAL_SECTION g_fc_lock;             // Khóa dùng để đồng bộ (thread-safe)
static int g_fc_initialized = 0;               // Đánh dấu đã khởi tạo hay chưa

/* 
    Khởi tạo chuỗi filter
    ----------------------
    - Tạo CRITICAL_SECTION để bảo vệ vùng dữ liệu
    - Đặt bộ đếm filter về 0
    - Gán NULL cho toàn bộ mảng filter
*/
void init_filter_chain(void)
{
    if (!g_fc_initialized) {
        InitializeCriticalSection(&g_fc_lock);
        g_filter_count = 0;
        for (int i = 0; i < MAX_FILTERS; ++i) {
            g_filters[i] = NULL;
        }
        g_fc_initialized = 1;
    }
}

/*
    Giải phóng chuỗi filter
    ------------------------
    - Xóa toàn bộ filter
    - Giải phóng CRITICAL_SECTION
*/
void shutdown_filter_chain(void)
{
    if (g_fc_initialized) {
        EnterCriticalSection(&g_fc_lock);
        g_filter_count = 0;
        for (int i = 0; i < MAX_FILTERS; ++i) {
            g_filters[i] = NULL;
        }
        LeaveCriticalSection(&g_fc_lock);
        DeleteCriticalSection(&g_fc_lock);
        g_fc_initialized = 0;
    }
}

/*
    Đăng ký thêm một filter mới
    ----------------------------
    - Mỗi filter là một hàm kiểu filter_fn_t
    - Chỉ thêm được tối đa MAX_FILTERS bộ lọc
    - Nếu chưa khởi tạo thì tự động init
    - Thread-safe bằng CRITICAL_SECTION
*/
int register_filter(filter_fn_t fn)
{
    if (!fn) return -1;
    if (!g_fc_initialized) init_filter_chain();

    EnterCriticalSection(&g_fc_lock);
    int rc = 0;
    if (g_filter_count >= MAX_FILTERS) {
        rc = -1; // Vượt quá giới hạn
    } else {
        g_filters[g_filter_count++] = fn; // Thêm filter vào danh sách
        rc = 0;
    }
    LeaveCriticalSection(&g_fc_lock);
    return rc;
}

FilterResult run_filters(FilterContext *ctx)
{
    if (!g_fc_initialized) init_filter_chain();

    // Lấy số lượng filter hiện tại
    int count;
    EnterCriticalSection(&g_fc_lock);
    count = g_filter_count;
    LeaveCriticalSection(&g_fc_lock);

    for (int i = 0; i < count; ++i) {
        filter_fn_t fn;

        // Đọc con trỏ filter an toàn (mảng chỉ thêm, không xóa)
        EnterCriticalSection(&g_fc_lock);
        fn = g_filters[i];
        LeaveCriticalSection(&g_fc_lock);

        if (!fn) continue;
        FilterResult r = fn(ctx);

        // Nếu filter trả về lỗi thì dừng ngay chuỗi
        if (r != FILTER_OK) {
            return r;
        }
    }
    return FILTER_OK;
}
