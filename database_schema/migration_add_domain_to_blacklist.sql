-- Migration: Add domain column to blacklist table
-- Date: 2025-11-23
-- Description: Chuyển đổi bảng blacklist từ global IP ban sang domain-specific IP ban

-- Bước 1: Thêm cột domain (tạm thời cho phép NULL)
ALTER TABLE blacklist ADD COLUMN domain VARCHAR(253) NULL AFTER ip;

-- Bước 2: Cập nhật tất cả records hiện tại với domain = '*' (global ban)
UPDATE blacklist SET domain = '*' WHERE domain IS NULL;

-- Bước 3: Thay đổi domain thành NOT NULL với default value
ALTER TABLE blacklist MODIFY COLUMN domain VARCHAR(253) NOT NULL DEFAULT '*';

-- Bước 4: Drop primary key cũ (chỉ ip)
ALTER TABLE blacklist DROP PRIMARY KEY;

-- Bước 5: Thêm primary key mới (ip + domain)
ALTER TABLE blacklist ADD PRIMARY KEY (ip, domain);

-- Bước 6: Thêm indexes mới
ALTER TABLE blacklist ADD INDEX idx_ip (ip);
ALTER TABLE blacklist ADD INDEX idx_domain (domain);

-- Bước 7: Cập nhật comment
ALTER TABLE blacklist COMMENT = 'IP blacklist for ACL filter (per domain or global with *)';

-- Kiểm tra kết quả
SELECT * FROM blacklist ORDER BY ip, domain;
