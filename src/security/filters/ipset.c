#include "ipset.h"
#include <stdio.h>
#include <string.h>


static CRITICAL_SECTION ipset_lock;
static int ipset_lock_initialized = 0;

void ipset_global_lock_init() {
    if (!ipset_lock_initialized) {
        InitializeCriticalSection(&ipset_lock);
        ipset_lock_initialized = 1;
    }
}

void ipset_init(ipset_t *s) {
    s->count = 0;
}

int ipset_add(ipset_t *s, const char *ip) {
    if (s->count >= MAX_IPS) return -1;
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0)
            return 0; // đã có rồi
    }
    strncpy(s->list[s->count].ip, ip, sizeof(s->list[s->count].ip) - 1);
    s->list[s->count].ip[sizeof(s->list[s->count].ip) - 1] = '\0';
    s->count++;
    return 1;
}

int ipset_remove(ipset_t *s, const char *ip) {
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0) {
            for (int j = i; j < s->count - 1; j++)
                s->list[j] = s->list[j + 1];
            s->count--;
            return 1;
        }
    }
    return 0;
}

int ipset_contains(ipset_t *s, const char *ip) {
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->list[i].ip, ip) == 0)
            return 1;
    }
    return 0;
}

/* Load từ file, mỗi dòng 1 IP, bỏ qua comment (#) và dòng trống */
int ipset_load(ipset_t *s, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    s->count = 0; // clear cũ
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        ipset_add(s, p);
    }
    fclose(f);
    return s->count;
}

int ip_exists_in_file(const char *path, const char *ip) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strcmp(line, ip) == 0) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}


int ipset_save(ipset_t *s, const char *path, const char *ip) {
    if (!s || !ip) {
        printf("[ACL] ipset_save: tham so NULL\n");
        return -1;
    }

    // Khởi tạo lock nếu chưa có
    ipset_global_lock_init();
    EnterCriticalSection(&ipset_lock);

    // Kiểm tra IP đã có chưa
    if (ip_exists_in_file(path, ip)) {
        printf("[ACL] %s da co trong blacklist (file), boqua\n", ip);
        LeaveCriticalSection(&ipset_lock);
        return 0;
    }

    // Thêm vào RAM
    ipset_add(s, ip);
    printf("[ACL] Dang them %s vao blacklist...\n", ip);

    // Ghi thêm vào file (append)
    FILE *f = fopen(path, "a");
    if (!f) {
        DWORD err = GetLastError();
        printf("[ACL] khong mo duoc file '%s' (errno=%d, winerr=%lu)\n",
               path, errno, err);
        LeaveCriticalSection(&ipset_lock);
        return -1;
    }

    fprintf(f, "%s\n", ip);
    fclose(f);
    printf("[ACL] Da ghi '%s' vao file %s\n", ip, path);

    LeaveCriticalSection(&ipset_lock);
    return 1;
}

