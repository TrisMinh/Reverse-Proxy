#ifndef IPSET_H
#define IPSET_H

/* ===========================================================
   ĐỊNH NGHĨA CẤU TRÚC CACHE
   =========================================================== */
#define MAX_IPS 10000

typedef struct {
    char ip[64];
} ip_entry_t;

typedef struct {
    ip_entry_t list[MAX_IPS];
    int count;
} ipset_t;

/* ===========================================================
   HÀM KHỞI TẠO & CƠ BẢN CHO CACHE
   =========================================================== */
void ipset_global_lock_init(void);
void ipset_init(ipset_t *s);
int  ipset_add(ipset_t *s, const char *ip);
int  ipset_remove(ipset_t *s, const char *ip);
int  ipset_contains(ipset_t *s, const char *ip);

/* ===========================================================
   MYSQL CORE
   =========================================================== */
int  ipdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port);
void ipdb_close(void);

/* ===========================================================
   MYSQL CRUD (Thao tác trực tiếp DB)
   =========================================================== */
int  ipdb_add(const char *ip);                          // CREATE
int  ipdb_exists(const char *ip);                       // READ
int  ipdb_remove(const char *ip);                       // DELETE
int  ipdb_load_all(ipset_t *s);                         // LOAD DB → cache

/* ===========================================================
   WRAPPER CRUD (Đồng bộ cache + DB)
   =========================================================== */
int  ipset_save(ipset_t *s, const char *unused, const char *ip);   // Add IP (cache + DB)
int  ipset_delete(ipset_t *s, const char *ip);                     // Remove IP (cache + DB)
int  ipset_reload(ipset_t *s);                                     // Reload DB → cache

/* ===========================================================
   GHI CHÚ:
   - Gọi ipdb_connect() trước khi thao tác DB.
   - Gọi ipdb_close() khi tắt proxy.
   - Cache lưu trong RAM (ipset_t), DB lưu vĩnh viễn.
   - Các hàm đều thread-safe (CriticalSection).
   =========================================================== */

#endif
