-- database name: proxy
CREATE TABLE IF NOT EXISTS users (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username        VARCHAR(64) NOT NULL UNIQUE,
  email           VARCHAR(255) NOT NULL UNIQUE,
  password_hash   VARCHAR(255) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User accounts & roles';

CREATE TABLE IF NOT EXISTS domains (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id       BIGINT UNSIGNED NOT NULL,
  domain        VARCHAR(253) NOT NULL,
  status        ENUM('active','paused','deleted') NOT NULL DEFAULT 'active',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_domains_user_domain (user_id, domain),
  CONSTRAINT fk_domains_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Domains onboarded to the proxy';

CREATE TABLE IF NOT EXISTS domain_origins (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  domain_id     BIGINT UNSIGNED NOT NULL,
  origin_ip     VARCHAR(45) NOT NULL, 
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_origins_domain (domain_id),
  CONSTRAINT fk_origins_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Multiple backend origin IPs per domain';
CREATE TABLE IF NOT EXISTS blacklist (
  ip            VARCHAR(45) NOT NULL,
  domain        VARCHAR(253) NOT NULL DEFAULT '*',
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (ip, domain),
  INDEX idx_ip (ip),
  INDEX idx_domain (domain),
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci 
COMMENT='IP blacklist for ACL filter (per domain or global with *)';
CREATE TABLE IF NOT EXISTS metrics_minute (
  ts_minute     DATETIME NOT NULL,
  domain_id     BIGINT UNSIGNED NOT NULL,
  host          VARCHAR(255) NOT NULL,
  route_bucket  VARCHAR(255) NOT NULL,
  method        ENUM('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','OTHER') NOT NULL,
  status_class  ENUM('2xx','3xx','4xx','5xx') NOT NULL,
  requests      INT UNSIGNED NOT NULL,
  bytes_in      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  bytes_out     BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (ts_minute, domain_id, host, route_bucket, method, status_class),
  KEY idx_mm_domain_time (domain_id, ts_minute),
  KEY idx_mm_route (domain_id, route_bucket),
  KEY idx_mm_timestamp (ts_minute DESC),
  CONSTRAINT fk_metrics_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Per-minute aggregated request metrics';
CREATE TABLE IF NOT EXISTS request_minute_summary (
  id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  timestamp           DATETIME NOT NULL,
  domain_id            BIGINT UNSIGNED NOT NULL,
  total_requests      INT UNSIGNED NOT NULL DEFAULT 0,
  requests_2xx        INT UNSIGNED NOT NULL DEFAULT 0,
  requests_4xx        INT UNSIGNED NOT NULL DEFAULT 0,
  requests_5xx        INT UNSIGNED NOT NULL DEFAULT 0,
  total_bytes_in      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  total_bytes_out     BIGINT UNSIGNED NOT NULL DEFAULT 0,
  peak_requests_min   INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  UNIQUE KEY uk_timestamp_domain (timestamp, domain_id),
  KEY idx_domain_time (domain_id, timestamp),
  INDEX idx_timestamp_desc (timestamp DESC),
  CONSTRAINT fk_rms_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci 
COMMENT='Minute-level aggregated request summary (per domain)';
CREATE TABLE IF NOT EXISTS cache_stats_minute (
  ts_minute      DATETIME NOT NULL,
  domain_id      BIGINT UNSIGNED NOT NULL,
  host           VARCHAR(255) NOT NULL,
  route_bucket   VARCHAR(255) NOT NULL,
  hit            INT UNSIGNED NOT NULL DEFAULT 0,
  miss           INT UNSIGNED NOT NULL DEFAULT 0,
  byte_hit       BIGINT UNSIGNED NOT NULL DEFAULT 0,
  byte_miss      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (ts_minute, domain_id, host, route_bucket),
  KEY idx_csm_domain_time (domain_id, ts_minute),
  KEY idx_csm_timestamp (ts_minute DESC),
  CONSTRAINT fk_cache_stats_domain FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Per-minute cache performance indicators (per route)';
