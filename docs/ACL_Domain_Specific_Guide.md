# Hướng Dẫn Sử Dụng ACL Theo Domain

## Tổng Quan

Hệ thống ACL đã được nâng cấp để hỗ trợ blacklist theo từng domain thay vì chặn toàn cục. Điều này cho phép:
- Chặn một IP chỉ ở một domain cụ thể
- Chặn một IP trên tất cả các domain (global ban với domain = `*`)
- Linh hoạt quản lý blacklist theo từng dịch vụ

## Thay Đổi Chính

### 1. Cấu Trúc Database
Bảng `blacklist` đã được cập nhật:
```sql
CREATE TABLE blacklist (
  ip            VARCHAR(45) NOT NULL,
  domain        VARCHAR(253) NOT NULL DEFAULT '*',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip, domain),
  INDEX idx_ip (ip),
  INDEX idx_domain (domain)
);
```

**Lưu ý:** Domain `*` được sử dụng cho global ban (chặn trên tất cả domain)

### 2. API Functions

#### `acl_add(ip, domain)`
Thêm IP vào blacklist cho domain cụ thể
```c
// Chặn IP 192.168.1.100 chỉ ở domain example.com
acl_add("192.168.1.100", "example.com");

// Chặn IP 10.0.0.1 trên tất cả domain
acl_add("10.0.0.1", "*");
// hoặc
acl_add("10.0.0.1", NULL);
```

#### `acl_remove(ip, domain)`
Xóa IP khỏi blacklist cho domain cụ thể
```c
// Bỏ chặn IP ở domain cụ thể
acl_remove("192.168.1.100", "example.com");

// Bỏ chặn global ban
acl_remove("10.0.0.1", "*");
```

### 3. Filter Logic

Khi filter kiểm tra request:
1. Lấy domain từ request context (từ route matching)
2. Kiểm tra xem IP có bị ban ở domain đó không
3. Kiểm tra xem IP có bị global ban không (domain = `*`)
4. Nếu một trong hai điều kiện trên đúng → FILTER_DENY

**Ví dụ:**
```
Request: IP 1.2.3.4 → domain example.com

Blacklist:
- 1.2.3.4 @ example.com   ← Bị chặn ✗
- 1.2.3.4 @ other.com     ← Không ảnh hưởng
- 5.6.7.8 @ *             ← Không ảnh hưởng

Request: IP 5.6.7.8 → domain example.com
- 5.6.7.8 @ *             ← Bị chặn ✗ (global ban)
```

## Migration Database

### Bước 1: Backup Database
```bash
mysqldump -u root -p proxy > backup_proxy_$(date +%Y%m%d).sql
```

### Bước 2: Chạy Migration Script
```bash
mysql -u root -p proxy < database_schema/migration_add_domain_to_blacklist.sql
```

Script này sẽ:
1. Thêm cột `domain` vào bảng `blacklist`
2. Cập nhật tất cả records hiện tại với `domain = '*'` (chuyển thành global ban)
3. Cập nhật primary key từ `(ip)` sang `(ip, domain)`
4. Thêm các indexes cần thiết

### Bước 3: Rebuild Application
```bash
make clean
make
```

## Ví Dụ Sử Dụng

### 1. Thêm Blacklist Entry Qua SQL
```sql
-- Chặn IP chỉ ở một domain cụ thể
INSERT INTO blacklist (ip, domain, created_at) 
VALUES ('192.168.1.100', 'api.example.com', NOW());

-- Chặn IP trên tất cả domain
INSERT INTO blacklist (ip, domain, created_at) 
VALUES ('10.0.0.50', '*', NOW());
```

### 2. Kiểm Tra Blacklist
```sql
-- Xem tất cả blacklist entries
SELECT ip, domain, created_at 
FROM blacklist 
ORDER BY created_at DESC;

-- Xem các IP bị chặn ở domain cụ thể
SELECT ip, created_at 
FROM blacklist 
WHERE domain = 'example.com' OR domain = '*';

-- Xem các global bans
SELECT ip, created_at 
FROM blacklist 
WHERE domain = '*';

-- Kiểm tra IP có bị chặn ở domain nào không
SELECT domain 
FROM blacklist 
WHERE ip = '192.168.1.100';
```

### 3. Xóa Blacklist Entry
```sql
-- Xóa ban ở domain cụ thể
DELETE FROM blacklist 
WHERE ip = '192.168.1.100' AND domain = 'api.example.com';

-- Xóa global ban
DELETE FROM blacklist 
WHERE ip = '10.0.0.50' AND domain = '*';

-- Xóa tất cả bans cho một IP
DELETE FROM blacklist 
WHERE ip = '192.168.1.100';
```

## Use Cases

### Case 1: Chặn Attacker Chỉ Ở API Domain
```sql
-- Phát hiện một IP đang tấn công API
INSERT INTO blacklist (ip, domain) 
VALUES ('123.45.67.89', 'api.example.com');

-- IP này vẫn có thể truy cập www.example.com
```

### Case 2: Chặn Toàn Bộ (Global Ban)
```sql
-- Phát hiện một IP độc hại nghiêm trọng
INSERT INTO blacklist (ip, domain) 
VALUES ('200.100.50.25', '*');

-- IP này bị chặn ở TẤT CẢ domain
```

### Case 3: Chặn Một IP Ở Nhiều Domain Cụ Thể
```sql
INSERT INTO blacklist (ip, domain) VALUES 
  ('111.222.333.444', 'api.example.com'),
  ('111.222.333.444', 'admin.example.com'),
  ('111.222.333.444', 'cdn.example.com');
```

## Testing

### Test 1: Domain-Specific Block
```bash
# Thêm blacklist entry
mysql -u root -p -e "INSERT INTO proxy.blacklist (ip, domain) VALUES ('192.168.1.100', 'api.example.com');"

# Restart hoặc reload proxy
./proxy

# Test request từ IP đó
curl -H "Host: api.example.com" http://proxy-server/  # → 403 Forbidden
curl -H "Host: www.example.com" http://proxy-server/  # → 200 OK
```

### Test 2: Global Block
```bash
# Thêm global ban
mysql -u root -p -e "INSERT INTO proxy.blacklist (ip, domain) VALUES ('10.0.0.50', '*');"

# Test request
curl -H "Host: api.example.com" http://proxy-server/  # → 403 Forbidden
curl -H "Host: www.example.com" http://proxy-server/  # → 403 Forbidden
curl -H "Host: cdn.example.com" http://proxy-server/  # → 403 Forbidden
```

## Backward Compatibility

Tất cả IP trong blacklist cũ sẽ được tự động chuyển thành global ban (domain = `*`) sau khi chạy migration script. Điều này đảm bảo:
- Không có IP nào bị "unban" do lỗi migration
- Hệ thống hoạt động ngay lập tức sau migration
- Admin có thể dần dần điều chỉnh sang domain-specific ban nếu cần

## Performance Considerations

1. **Index Optimization:** Cả `ip` và `domain` đều có index riêng để tối ưu query
2. **Primary Key:** Composite key `(ip, domain)` đảm bảo không có duplicate
3. **Memory Cache:** ipset_t cache trong memory vẫn hoạt động hiệu quả với cấu trúc mới

## Troubleshooting

### Lỗi: Duplicate Entry
```
ERROR 1062: Duplicate entry '192.168.1.1-example.com' for key 'PRIMARY'
```
**Giải pháp:** IP này đã bị chặn ở domain đó rồi. Kiểm tra:
```sql
SELECT * FROM blacklist WHERE ip = '192.168.1.1' AND domain = 'example.com';
```

### Lỗi: Migration Failed
Nếu migration script báo lỗi, có thể bảng đã được modify. Restore từ backup:
```bash
mysql -u root -p proxy < backup_proxy_YYYYMMDD.sql
```

## Future Enhancements

1. **Web UI:** Thêm giao diện quản lý blacklist theo domain
2. **Auto-ban:** Tự động ban IP khi phát hiện tấn công ở domain cụ thể
3. **Whitelist per Domain:** Tương tự blacklist nhưng cho whitelist
4. **Time-based Ban:** Thêm expiry time cho mỗi ban entry
