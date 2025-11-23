# ACL Domain-Specific Examples

## Ví Dụ Thực Tế

### Scenario 1: E-commerce Website với nhiều subdomain

**Cấu trúc:**
- `www.shop.com` - Trang chủ
- `api.shop.com` - API backend
- `admin.shop.com` - Admin panel

**Tình huống:** Phát hiện một IP đang tấn công brute-force vào admin panel

```sql
-- Chặn IP chỉ ở admin panel, không ảnh hưởng đến khách hàng browsing web hoặc dùng API
INSERT INTO blacklist (ip, domain) VALUES ('45.67.89.123', 'admin.shop.com');
```

**Kết quả:**
- ✗ `45.67.89.123` → `admin.shop.com` - BLOCKED
- ✓ `45.67.89.123` → `www.shop.com` - OK
- ✓ `45.67.89.123` → `api.shop.com` - OK

---

### Scenario 2: API Rate Limit Auto-Ban

**Tình huống:** Một client vi phạm rate limit 5 lần liên tiếp

**Code trong rate_limit.c:**
```c
if (count >= 5) {
    const char *domain = (ctx->route && ctx->route->domain) ? ctx->route->domain : "*";
    acl_add(ctx->client_ip, domain);
}
```

**Kết quả:** IP bị auto-ban chỉ ở domain mà nó đang spam, không ảnh hưởng domain khác

---

### Scenario 3: Known Malicious IP - Global Ban

**Tình huống:** Phát hiện một IP từ botnet đã được report trên threat intelligence

```sql
-- Chặn toàn bộ trên tất cả domain
INSERT INTO blacklist (ip, domain) VALUES ('123.45.67.89', '*');
```

**Kết quả:**
- ✗ `123.45.67.89` → Bất kỳ domain nào - BLOCKED

---

### Scenario 4: Temporary Block một Region

**Tình huống:** Phát hiện một cuộc tấn công DDoS từ một dải IP cụ thể

```sql
-- Chặn nhiều IP cùng lúc ở domain bị tấn công
INSERT INTO blacklist (ip, domain) VALUES 
  ('100.101.102.1', 'api.shop.com'),
  ('100.101.102.2', 'api.shop.com'),
  ('100.101.102.3', 'api.shop.com'),
  ('100.101.102.4', 'api.shop.com');
```

**Sau khi tấn công kết thúc:**
```sql
-- Unban tất cả
DELETE FROM blacklist WHERE domain = 'api.shop.com' AND ip LIKE '100.101.102.%';
```

---

### Scenario 5: Development Environment Protection

**Tình huống:** Dev environment chỉ cho phép IP công ty, block tất cả IP khác

```sql
-- Whitelist approach: Thêm tất cả IP không phải công ty vào blacklist
-- (Hoặc dùng firewall rules, nhưng có thể dùng ACL cho flexibility)

-- Ví dụ: Cho phép office IP, block global
INSERT INTO blacklist (ip, domain) 
SELECT ip, 'dev.shop.com'
FROM (
    -- Logic để generate list IPs cần block
    -- Thực tế nên dùng whitelist filter riêng
) AS ips_to_block;
```

---

### Scenario 6: Progressive Ban Strategy

**Tình huống:** Tăng dần mức độ chặn dựa trên behavior

**Step 1:** Phát hiện suspicious behavior ở API
```sql
INSERT INTO blacklist (ip, domain) VALUES ('200.100.50.25', 'api.shop.com');
```

**Step 2:** IP tiếp tục tấn công ở domain khác → Nâng cấp lên global ban
```sql
-- Delete domain-specific ban
DELETE FROM blacklist WHERE ip = '200.100.50.25' AND domain = 'api.shop.com';

-- Add global ban
INSERT INTO blacklist (ip, domain) VALUES ('200.100.50.25', '*');
```

---

## Query Patterns Hữu Ích

### 1. Xem tất cả bans của một IP
```sql
SELECT ip, domain, created_at 
FROM blacklist 
WHERE ip = '192.168.1.100'
ORDER BY created_at DESC;
```

### 2. Xem tất cả IPs bị ban ở một domain (bao gồm global bans)
```sql
SELECT ip, domain, created_at 
FROM blacklist 
WHERE domain = 'api.shop.com' OR domain = '*'
ORDER BY created_at DESC;
```

### 3. Đếm số lượng bans theo domain
```sql
SELECT domain, COUNT(*) as ban_count
FROM blacklist
GROUP BY domain
ORDER BY ban_count DESC;
```

### 4. Tìm IPs có nhiều bans (bị ban ở nhiều domain)
```sql
SELECT ip, COUNT(*) as domain_count, GROUP_CONCAT(domain) as domains
FROM blacklist
WHERE domain != '*'
GROUP BY ip
HAVING domain_count > 1
ORDER BY domain_count DESC;
```

### 5. Tìm Global Bans
```sql
SELECT ip, created_at 
FROM blacklist 
WHERE domain = '*'
ORDER BY created_at DESC;
```

### 6. Recent Bans (24h qua)
```sql
SELECT ip, domain, created_at 
FROM blacklist 
WHERE created_at >= NOW() - INTERVAL 24 HOUR
ORDER BY created_at DESC;
```

### 7. Chuyển đổi Domain-Specific Ban thành Global Ban
```sql
-- Xóa tất cả domain-specific bans của IP
DELETE FROM blacklist WHERE ip = '192.168.1.100' AND domain != '*';

-- Thêm global ban
INSERT INTO blacklist (ip, domain) VALUES ('192.168.1.100', '*');
```

### 8. Cleanup Old Bans (> 30 ngày)
```sql
DELETE FROM blacklist 
WHERE created_at < NOW() - INTERVAL 30 DAY 
  AND domain != '*';  -- Giữ lại global bans
```

---

## Integration với Monitoring

### Log Pattern Analysis
```sql
-- Tạo view để phân tích bans theo thời gian
CREATE VIEW v_ban_timeline AS
SELECT 
    DATE(created_at) as ban_date,
    domain,
    COUNT(*) as bans_count
FROM blacklist
GROUP BY DATE(created_at), domain
ORDER BY ban_date DESC, bans_count DESC;

-- Query
SELECT * FROM v_ban_timeline WHERE ban_date >= CURDATE() - INTERVAL 7 DAY;
```

### Alert on Suspicious Pattern
```sql
-- Phát hiện IP bị ban ở quá nhiều domain (có thể là false positive)
SELECT ip, COUNT(DISTINCT domain) as domain_count
FROM blacklist
WHERE domain != '*'
  AND created_at >= NOW() - INTERVAL 1 HOUR
GROUP BY ip
HAVING domain_count >= 3;
```

---

## Best Practices

### ✅ DO:
1. **Domain-specific ban** cho rate limit violations
2. **Global ban** cho known malicious IPs
3. Monitor ban statistics để phát hiện patterns
4. Định kỳ review và cleanup old bans
5. Log mọi thao tác add/remove ban

### ❌ DON'T:
1. Đừng ban toàn bộ subnet bằng cách insert từng IP (sử dụng CIDR matching nếu cần)
2. Đừng để bans accumulate vô hạn (cleanup strategy)
3. Đừng ban IP của load balancer hoặc proxy (use X-Forwarded-For)

---

## Testing Commands

### Test Domain-Specific Ban
```bash
# Terminal 1: Add ban
mysql -u root -p -e "INSERT INTO proxy.blacklist (ip, domain) VALUES ('192.168.1.100', 'api.shop.com');"

# Terminal 2: Test
curl -H "Host: api.shop.com" http://localhost:8080/      # → 403
curl -H "Host: www.shop.com" http://localhost:8080/      # → 200
```

### Test Global Ban
```bash
# Terminal 1: Add global ban
mysql -u root -p -e "INSERT INTO proxy.blacklist (ip, domain) VALUES ('10.0.0.1', '*');"

# Terminal 2: Test  
curl -H "Host: api.shop.com" http://localhost:8080/      # → 403
curl -H "Host: www.shop.com" http://localhost:8080/      # → 403
curl -H "Host: cdn.shop.com" http://localhost:8080/      # → 403
```

### Test Ban Removal
```bash
# Remove ban
mysql -u root -p -e "DELETE FROM proxy.blacklist WHERE ip='192.168.1.100' AND domain='api.shop.com';"

# Reload ACL (hoặc đợi auto-reload)
# Gửi SIGHUP signal hoặc restart proxy

# Test lại
curl -H "Host: api.shop.com" http://localhost:8080/      # → 200 OK
```
