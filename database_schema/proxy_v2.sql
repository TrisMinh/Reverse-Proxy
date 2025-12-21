-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 21, 2025 at 01:57 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `proxy`
--

-- --------------------------------------------------------

--
-- Table structure for table `blacklist`
--

CREATE TABLE `blacklist` (
  `ip` varchar(45) NOT NULL,
  `domain` varchar(20) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='IP blacklist for ACL filter';

-- --------------------------------------------------------

--
-- Table structure for table `cache_stats_minute`
--

CREATE TABLE `cache_stats_minute` (
  `ts_minute` datetime NOT NULL,
  `domain_id` bigint(20) UNSIGNED NOT NULL,
  `host` varchar(255) NOT NULL,
  `route_bucket` varchar(255) NOT NULL,
  `hit` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `miss` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `byte_hit` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `byte_miss` bigint(20) UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Per-minute cache performance indicators (per route)';

--
-- Dumping data for table `cache_stats_minute`
--

INSERT INTO `cache_stats_minute` (`ts_minute`, `domain_id`, `host`, `route_bucket`, `hit`, `miss`, `byte_hit`, `byte_miss`) VALUES
('2025-12-19 19:46:00', 1, 'localhost', '/', 0, 2, 0, 924),
('2025-12-19 19:46:00', 1, 'localhost', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/css/style.css', 0, 3, 0, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/favicon.ico', 0, 1, 0, 150),
('2025-12-19 19:46:00', 1, 'localhost', '/images/galaxy.png', 0, 3, 0, 42520),
('2025-12-19 19:46:00', 1, 'localhost', '/js/script.js', 0, 3, 0, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/products', 0, 1, 0, 1102),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/', 0, 1, 0, 145),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/auth/login', 0, 3, 0, 1138),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/css/style.css', 0, 2, 0, 0),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/js/script.js', 0, 2, 0, 0),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/products', 0, 1, 0, 46),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/auth/login', 0, 2, 0, 1301),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/auth/loginUNION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1', 0, 1, 0, 233),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/css/style.css', 0, 1, 0, 0),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/js/script.js', 0, 1, 0, 0),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/auth/login', 0, 2, 0, 1301),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 1076),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/css/style.css', 0, 1, 0, 0),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/js/script.js', 0, 1, 0, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 0, 1, 0, 924),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 0, 1, 0, 1076),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201?q=union%20sele', 0, 1, 0, 1076),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/css/style.css', 0, 2, 0, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/js/script.js', 0, 2, 0, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/css/style.css', 0, 1, 0, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/images/galaxy.png', 0, 1, 0, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/js/script.js', 0, 1, 0, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/', 0, 1, 0, 924),
('2025-12-19 19:52:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 5, 0, 924),
('2025-12-19 19:52:00', 1, 'localhost', '/?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 0, 1, 0, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/css/style.css', 0, 2, 0, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/images/galaxy.png', 0, 2, 0, 42520),
('2025-12-19 19:52:00', 1, 'localhost', '/js/script.js', 0, 2, 0, 0),
('2025-12-19 19:53:00', 1, 'localhost', '/css/style.css', 0, 1, 0, 0),
('2025-12-19 19:53:00', 1, 'localhost', '/images/galaxy.png', 0, 1, 0, 42520),
('2025-12-19 19:53:00', 1, 'localhost', '/js/script.js', 0, 1, 0, 0),
('2025-12-19 19:53:00', 1, 'localhost', '/products', 0, 1, 0, 1102),
('2025-12-19 19:55:00', 1, 'localhost', '/', 0, 2, 0, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/css/style.css', 0, 3, 0, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/images/galaxy.png', 0, 3, 0, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/js/script.js', 0, 3, 0, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/products', 0, 1, 0, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/products?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 6, 0, 1102),
('2025-12-19 19:56:00', 1, 'localhost', '/products?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 20:08:00', 1, 'localhost', '/phpmyadmin/index.php?route=/', 0, 1, 0, 160),
('2025-12-19 20:09:00', 1, 'localhost', '/', 0, 1, 0, 924),
('2025-12-19 20:09:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 20:09:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 0, 1, 0, 187),
('2025-12-19 20:09:00', 1, 'localhost', '/css/style.css', 0, 1, 0, 0),
('2025-12-19 20:09:00', 1, 'localhost', '/images/galaxy.png', 0, 1, 0, 42520),
('2025-12-19 20:09:00', 1, 'localhost', '/js/script.js', 0, 1, 0, 0),
('2025-12-19 20:09:00', 1, 'localhost', '/products?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 20:22:00', 1, 'localhost', '/', 0, 1, 0, 924),
('2025-12-19 20:22:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 2, 0, 924),
('2025-12-19 20:22:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 0, 1, 0, 187),
('2025-12-19 20:22:00', 1, 'localhost', '/css/style.css', 0, 1, 0, 0),
('2025-12-19 20:22:00', 1, 'localhost', '/images/galaxy.png', 0, 1, 0, 42520),
('2025-12-19 20:22:00', 1, 'localhost', '/js/script.js', 0, 1, 0, 0),
('2025-12-19 20:23:00', 1, 'localhost', '/', 0, 2, 0, 924),
('2025-12-19 20:23:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 924),
('2025-12-19 20:23:00', 1, 'localhost', '/css/style.css', 0, 2, 0, 0),
('2025-12-19 20:23:00', 1, 'localhost', '/images/galaxy.png', 0, 2, 0, 85040),
('2025-12-19 20:23:00', 1, 'localhost', '/js/script.js', 0, 2, 0, 0),
('2025-12-19 20:24:00', 1, 'localhost', '/?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 0, 2, 0, 924),
('2025-12-19 20:24:00', 1, 'localhost', '/css/style.css', 0, 2, 0, 0),
('2025-12-19 20:24:00', 1, 'localhost', '/images/galaxy.png', 0, 2, 0, 0),
('2025-12-19 20:24:00', 1, 'localhost', '/js/script.js', 0, 2, 0, 0),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/', 0, 1, 0, 850),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 1, 0, 9379),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 1, 0, 4242),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 1, 0, 2257940),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 1, 0, 42520),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 1, 0, 25477),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 0, 1, 0, 9379),
('2025-12-19 20:33:00', 1, 'localhost', '/', 0, 1, 0, 2375),
('2025-12-19 20:33:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 2375),
('2025-12-19 20:33:00', 1, 'localhost', '//ws', 0, 2, 0, 0),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/audio/Song.mp3', 0, 3, 0, 3857933),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/css/style.css', 0, 1, 0, 0),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/images/BGR3.png', 0, 1, 0, 2257940),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/images/galaxy.png', 0, 2, 0, 42520),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/js/star.js', 0, 1, 0, 26414),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 3, 0, 4750),
('2025-12-19 20:34:00', 2, 'ngosing.online', '//ws', 0, 3, 0, 0),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 3, 0, 3889446),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/logim4?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/product?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 20:35:00', 2, 'ngosing.online', '/dangnhap?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 20:35:00', 2, 'ngosing.online', '/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 0, 1, 0, 0),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 3, 0, 3583123),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 1, 0, 0),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 2, 0, 42520),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 1, 0, 26414),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/dangnhap?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/', 0, 1, 0, 2375),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '//ws', 0, 2, 0, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 1, 0, 523923),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 2, 0, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 1, 0, 2257940),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 1, 0, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 2, 0, 4750),
('2025-12-19 23:20:00', 2, 'ngosing.online', '//ws', 0, 2, 0, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 4, 0, 929280),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 2, 0, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 2, 0, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 2, 0, 42520),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 2, 0, 26414),
('2025-12-20 11:52:00', 1, 'localhost', '/', 0, 2, 0, 924),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/auth/login', 0, 3, 0, 2377),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/css/style.css', 0, 2, 0, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/js/script.js', 0, 2, 0, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/products', 0, 1, 0, 46),
('2025-12-20 11:52:00', 1, 'localhost', '/css/style.css', 0, 1, 0, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/favicon.ico', 0, 1, 0, 150),
('2025-12-20 11:52:00', 1, 'localhost', '/images/galaxy.png', 0, 1, 0, 42520),
('2025-12-20 11:52:00', 1, 'localhost', '/js/script.js', 0, 1, 0, 0),
('2025-12-20 11:53:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 2, 0, 1076),
('2025-12-20 11:53:00', 1, 'localhost', '/admin/css/style.css', 0, 2, 0, 0),
('2025-12-20 11:53:00', 1, 'localhost', '/admin/js/script.js', 0, 2, 0, 0),
('2025-12-20 12:15:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHE', 0, 1, 0, 1076),
('2025-12-20 12:15:00', 1, 'localhost', '/admin/css/style.css', 0, 1, 0, 0),
('2025-12-20 12:15:00', 1, 'localhost', '/admin/js/script.js', 0, 1, 0, 0),
('2025-12-20 12:24:00', 1, 'localhost', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-20 12:24:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20union%20select%20union%20select%20union%20sele\\%C6%B0', 0, 1, 0, 1076),
('2025-12-20 12:24:00', 1, 'localhost', '/admin/css/style.css', 0, 1, 0, 0),
('2025-12-20 12:24:00', 1, 'localhost', '/admin/js/script.js', 0, 1, 0, 0),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/auth/login', 0, 2, 0, 188),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20union%20sele', 0, 2, 0, 1239),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/css/style.css', 0, 2, 0, 0),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/js/script.js', 0, 2, 0, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20union%20select', 0, 1, 0, 1076),
('2025-12-20 19:51:00', 1, 'localhost', '/admin/css/style.css', 0, 1, 0, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/admin/js/script.js', 0, 1, 0, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/favicon.ico', 0, 1, 0, 150),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/', 0, 1, 0, 2375),
('2025-12-21 00:11:00', 2, 'ngosing.online', '//ws', 0, 1, 0, 0),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 3, 0, 3583123),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 1, 0, 0),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 1, 0, 2257940),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 1, 0, 42520),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 1, 0, 26414),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/', 0, 1, 0, 2375),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-21 00:12:00', 2, 'ngosing.online', '//ws', 0, 1, 0, 0),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 3, 0, 3889446),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 1, 0, 0),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 1, 0, 2257940),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 1, 1, 42520, 42520),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 1, 0, 26414),
('2025-12-21 00:13:00', 1, 'localhost', '/', 3, 2, 2772, 1848),
('2025-12-21 00:13:00', 1, 'localhost', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-21 00:13:00', 1, 'localhost', '/css/style.css', 2, 2, 4712, 0),
('2025-12-21 00:13:00', 1, 'localhost', '/images/galaxy.png', 2, 2, 85040, 85040),
('2025-12-21 00:13:00', 1, 'localhost', '/js/script.js', 2, 2, 36, 0),
('2025-12-21 00:14:00', 1, 'localhost', '/', 8, 0, 7392, 0),
('2025-12-21 00:14:00', 1, 'localhost', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-21 00:14:00', 1, 'localhost', '/css/style.css', 8, 0, 18848, 0),
('2025-12-21 00:14:00', 1, 'localhost', '/images/galaxy.png', 8, 0, 340160, 0),
('2025-12-21 00:14:00', 1, 'localhost', '/js/script.js', 8, 0, 144, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/', 7, 14, 6468, 2772),
('2025-12-21 00:15:00', 1, 'localhost', '/css/style.css', 0, 22, 0, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/images/galaxy.png', 0, 21, 0, 85040),
('2025-12-21 00:15:00', 1, 'localhost', '/js/script.js', 0, 19, 0, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/products', 0, 1, 0, 1102),
('2025-12-21 00:16:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 0, 1, 0, 187),
('2025-12-21 00:16:00', 1, 'localhost', '/css/style.css', 0, 1, 0, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/', 0, 5, 0, 2375),
('2025-12-21 00:16:00', 2, 'ngosing.online', '//ws', 0, 4, 0, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 1, 0, 3506176),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 4, 0, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 4, 0, 2257940),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 4, 0, 42520),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 4, 0, 26414),
('2025-12-21 00:17:00', 1, 'localhost', '/', 0, 5, 0, 924),
('2025-12-21 00:17:00', 1, 'localhost', '/css/style.css', 0, 5, 0, 0),
('2025-12-21 00:17:00', 1, 'localhost', '/images/galaxy.png', 0, 5, 0, 0),
('2025-12-21 00:17:00', 1, 'localhost', '/js/script.js', 0, 5, 0, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/', 0, 8, 0, 4750),
('2025-12-21 00:17:00', 2, 'ngosing.online', '//ws', 0, 7, 0, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 4, 0, 371859),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 7, 0, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 7, 0, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 8, 0, 85040),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 7, 0, 52828),
('2025-12-21 00:19:00', 1, 'localhost', '/', 3, 6, 2772, 1848),
('2025-12-21 00:19:00', 1, 'localhost', '/css/style.css', 0, 10, 0, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/images/galaxy.png', 0, 10, 0, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/js/script.js', 0, 10, 0, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/products', 0, 18, 0, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/', 0, 98, 0, 2375),
('2025-12-21 00:19:00', 2, 'ngosing.online', '//ws', 0, 14, 0, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 2, 0, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 98, 0, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 98, 0, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 99, 0, 42520),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 98, 0, 26414),
('2025-12-21 00:20:00', 1, 'localhost', '/', 2, 0, 1848, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/css/style.css', 0, 12, 0, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/images/galaxy.png', 0, 12, 0, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/js/script.js', 0, 12, 0, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/products', 7, 40, 7714, 2204),
('2025-12-21 00:22:00', 1, 'localhost', '/', 2, 16, 1848, 924),
('2025-12-21 00:22:00', 1, 'localhost', '/css/style.css', 0, 8, 0, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/images/galaxy.png', 0, 8, 0, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/js/script.js', 0, 7, 0, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/products', 0, 2, 0, 1102),
('2025-12-21 00:29:00', 1, 'localhost', '/', 0, 1, 0, 924),
('2025-12-21 00:29:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 3, 0, 924),
('2025-12-21 00:29:00', 1, 'localhost', '/css/style.css', 0, 1, 0, 0),
('2025-12-21 00:29:00', 1, 'localhost', '/images/galaxy.png', 0, 1, 0, 0),
('2025-12-21 00:29:00', 1, 'localhost', '/js/script.js', 0, 1, 0, 0),
('2025-12-21 00:30:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-21 00:30:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 0, 2, 0, 374),
('2025-12-21 00:31:00', 1, 'localhost', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-21 00:31:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 924),
('2025-12-21 00:32:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-21 00:33:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-21 00:33:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 0, 2, 0, 374),
('2025-12-21 00:34:00', 2, 'ngosing.online', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-21 00:34:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 2375),
('2025-12-21 00:34:00', 2, 'ngosing.online', '//ws', 0, 1, 0, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 3, 0, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 0, 3, 0, 374),
('2025-12-21 00:36:00', 1, 'localhost', '/css/style.css', 0, 3, 0, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/images/galaxy.png', 0, 3, 0, 42520),
('2025-12-21 00:36:00', 1, 'localhost', '/js/script.js', 0, 3, 0, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 0, 1, 0, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '//ws', 0, 1, 0, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 1, 0, 3325587),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 1, 0, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 1, 0, 2257940),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 1, 0, 42520),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 1, 0, 26414),
('2025-12-21 00:48:00', 1, 'localhost', '/', 2, 16, 1848, 2772),
('2025-12-21 00:48:00', 1, 'localhost', '/__captcha/callback', 0, 1, 0, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/css/style.css', 0, 19, 0, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/images/galaxy.png', 0, 17, 0, 127560),
('2025-12-21 00:48:00', 1, 'localhost', '/js/script.js', 0, 16, 0, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/products', 0, 1, 0, 0),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/', 0, 2, 0, 4750),
('2025-12-21 19:33:00', 2, 'ngosing.online', '//ws', 0, 2, 0, 0),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 2, 0, 4107411),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/css/style.css', 0, 4, 0, 0),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 0, 2, 0, 4515880),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 2, 0, 85040),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/js/star.js', 0, 2, 0, 52828),
('2025-12-21 19:40:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 0, 2, 0, 2927763),
('2025-12-21 19:40:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/', 254, 11, 19050508, 825022),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kB_', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kH4&sid=DgM49WH8tgVjUHtcAACX', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kHA&sid=DgM49WH8tgVjUHtcAACX', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-khL', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-khX&sid=YTLYDi2MaNfLSOLeAACZ', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-khY&sid=YTLYDi2MaNfLSOLeAACZ', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kK-&sid=DgM49WH8tgVjUHtcAACX', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kmi&sid=YTLYDi2MaNfLSOLeAACZ', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lAg&sid=Tp1yYWgXrsR3jt4LAACb', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lAh&sid=Tp1yYWgXrsR3jt4LAACb', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lAT', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lfc', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lFd&sid=Tp1yYWgXrsR3jt4LAACb', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lfp&sid=xwkcjhBndpDwzu7yAACd', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lfq&sid=xwkcjhBndpDwzu7yAACd', 0, 1, 0, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lko&sid=xwkcjhBndpDwzu7yAACd', 0, 1, 0, 0);

-- --------------------------------------------------------

--
-- Table structure for table `domains`
--

CREATE TABLE `domains` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `domain` varchar(253) NOT NULL,
  `status` enum('active','paused','deleted') NOT NULL DEFAULT 'active',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Domains onboarded to the proxy';

--
-- Dumping data for table `domains`
--

INSERT INTO `domains` (`id`, `user_id`, `domain`, `status`, `created_at`, `updated_at`) VALUES
(1, 1, 'localhost', 'active', '2025-12-19 19:42:04', '2025-12-19 19:42:04'),
(2, 1, 'ngosing.online', 'active', '2025-12-19 20:29:27', '2025-12-19 20:29:27');

-- --------------------------------------------------------

--
-- Table structure for table `domain_origins`
--

CREATE TABLE `domain_origins` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `domain_id` bigint(20) UNSIGNED NOT NULL,
  `origin_ip` varchar(45) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `backend_port` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Multiple backend origin IPs per domain';

--
-- Dumping data for table `domain_origins`
--

INSERT INTO `domain_origins` (`id`, `domain_id`, `origin_ip`, `created_at`, `updated_at`, `backend_port`) VALUES
(1, 1, '127.0.0.1', '2025-12-19 19:42:19', '2025-12-20 11:51:18', 3000),
(3, 2, '127.0.0.1', '2025-12-19 20:30:05', '2025-12-19 20:33:25', 5501);

-- --------------------------------------------------------

--
-- Table structure for table `metrics_minute`
--

CREATE TABLE `metrics_minute` (
  `ts_minute` datetime NOT NULL,
  `domain_id` bigint(20) UNSIGNED NOT NULL,
  `host` varchar(255) NOT NULL,
  `route_bucket` varchar(255) NOT NULL,
  `method` enum('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','OTHER') NOT NULL,
  `status_class` enum('2xx','3xx','4xx','5xx') NOT NULL,
  `requests` int(10) UNSIGNED NOT NULL,
  `bytes_in` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `bytes_out` bigint(20) UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Per-minute aggregated request metrics';

--
-- Dumping data for table `metrics_minute`
--

INSERT INTO `metrics_minute` (`ts_minute`, `domain_id`, `host`, `route_bucket`, `method`, `status_class`, `requests`, `bytes_in`, `bytes_out`) VALUES
('2025-12-19 19:46:00', 1, 'localhost', '/', 'GET', '2xx', 1, 1606, 924),
('2025-12-19 19:46:00', 1, 'localhost', '/', 'GET', '3xx', 1, 1773, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/__captcha/callback', 'GET', '2xx', 1, 3241, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 1563, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 2, 3306, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/favicon.ico', 'GET', '4xx', 1, 1607, 150),
('2025-12-19 19:46:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 1, 1613, 42520),
('2025-12-19 19:46:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 2, 3408, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 1548, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 2, 3274, 0),
('2025-12-19 19:46:00', 1, 'localhost', '/products', 'GET', '2xx', 1, 1729, 1102),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/', 'GET', '4xx', 1, 1692, 145),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/auth/login', 'GET', '2xx', 2, 3481, 1076),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/auth/login', 'POST', '3xx', 1, 1875, 62),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/css/style.css', 'GET', '2xx', 1, 1585, 0),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 1, 1671, 0),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/js/script.js', 'GET', '2xx', 1, 1570, 0),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 1, 1657, 0),
('2025-12-19 19:47:00', 1, 'localhost', '/admin/products', 'GET', '3xx', 1, 1700, 46),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/auth/login', 'GET', '2xx', 1, 1779, 1239),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/auth/login', 'POST', '3xx', 1, 1875, 62),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/auth/loginUNION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1', 'GET', '4xx', 1, 1780, 233),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 1, 1671, 0),
('2025-12-19 19:48:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 1, 1657, 0),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/auth/login', 'GET', '2xx', 1, 1781, 1239),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/auth/login', 'POST', '3xx', 1, 1778, 62),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 1838, 1076),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 1, 1673, 0),
('2025-12-19 19:49:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 1, 1659, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 'GET', '2xx', 1, 1768, 924),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1890, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 'GET', '2xx', 1, 1790, 1076),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201?q=union%20sele', 'GET', '2xx', 1, 1776, 1076),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/css/style.css', 'GET', '2xx', 1, 1673, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 1, 1839, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/js/script.js', 'GET', '2xx', 1, 1658, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 1, 1825, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 1, 1731, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 1, 1782, 0),
('2025-12-19 19:50:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 1, 1715, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/', 'GET', '2xx', 1, 1686, 924),
('2025-12-19 19:52:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 1817, 924),
('2025-12-19 19:52:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 4, 7502, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 'GET', '3xx', 1, 1726, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 1563, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 1, 1735, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 1, 1613, 42520),
('2025-12-19 19:52:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 1, 1786, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 1548, 0),
('2025-12-19 19:52:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 1, 1719, 0),
('2025-12-19 19:53:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 1571, 0),
('2025-12-19 19:53:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 1, 1621, 42520),
('2025-12-19 19:53:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 1556, 0),
('2025-12-19 19:53:00', 1, 'localhost', '/products', 'GET', '2xx', 1, 1694, 1102),
('2025-12-19 19:55:00', 1, 'localhost', '/', 'GET', '3xx', 2, 3460, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 3, 4943, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 3, 5096, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 3, 4895, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/products', 'GET', '3xx', 1, 1777, 0),
('2025-12-19 19:55:00', 1, 'localhost', '/products?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 1821, 1102),
('2025-12-19 19:55:00', 1, 'localhost', '/products?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 5, 9495, 0),
('2025-12-19 19:56:00', 1, 'localhost', '/products?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1805, 0),
('2025-12-19 20:08:00', 1, 'localhost', '/phpmyadmin/index.php?route=/', 'POST', '4xx', 1, 1632, 160),
('2025-12-19 20:09:00', 1, 'localhost', '/', 'GET', '2xx', 1, 1717, 924),
('2025-12-19 20:09:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1867, 0),
('2025-12-19 20:09:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 'GET', '4xx', 1, 1409, 187),
('2025-12-19 20:09:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 1594, 0),
('2025-12-19 20:09:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 1, 1644, 42520),
('2025-12-19 20:09:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 1579, 0),
('2025-12-19 20:09:00', 1, 'localhost', '/products?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1901, 0),
('2025-12-19 20:22:00', 1, 'localhost', '/', 'GET', '2xx', 1, 782, 924),
('2025-12-19 20:22:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 778, 924),
('2025-12-19 20:22:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1642, 0),
('2025-12-19 20:22:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 'GET', '4xx', 1, 1254, 187),
('2025-12-19 20:22:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 659, 0),
('2025-12-19 20:22:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 1, 709, 42520),
('2025-12-19 20:22:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 644, 0),
('2025-12-19 20:23:00', 1, 'localhost', '/', 'GET', '2xx', 1, 680, 924),
('2025-12-19 20:23:00', 1, 'localhost', '/', 'GET', '3xx', 1, 829, 0),
('2025-12-19 20:23:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 882, 924),
('2025-12-19 20:23:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 2, 1289, 0),
('2025-12-19 20:23:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 2, 1389, 85040),
('2025-12-19 20:23:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 2, 1259, 0),
('2025-12-19 20:24:00', 1, 'localhost', '/?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 'GET', '2xx', 1, 837, 924),
('2025-12-19 20:24:00', 1, 'localhost', '/?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 'GET', '3xx', 1, 889, 0),
('2025-12-19 20:24:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 2, 1600, 0),
('2025-12-19 20:24:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 2, 1702, 0),
('2025-12-19 20:24:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 2, 1568, 0),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/', 'GET', '2xx', 1, 694, 850),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '4xx', 1, 583, 9379),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 584, 4242),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '2xx', 1, 632, 2257940),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 1, 634, 42520),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 567, 25477),
('2025-12-19 20:31:00', 2, 'ngosing.online', '/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 'GET', '4xx', 1, 785, 9379),
('2025-12-19 20:33:00', 1, 'localhost', '/', 'GET', '2xx', 1, 1466, 2375),
('2025-12-19 20:33:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 1616, 2375),
('2025-12-19 20:33:00', 1, 'localhost', '//ws', 'GET', '2xx', 2, 2528, 0),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/audio/Song.mp3', 'GET', '2xx', 2, 2679, 3857933),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/audio/Song.mp3', 'GET', '3xx', 1, 1416, 0),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/css/style.css', 'GET', '2xx', 1, 1350, 0),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/images/BGR3.png', 'GET', '2xx', 1, 1365, 2257940),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/images/galaxy.png', 'GET', '2xx', 1, 1367, 42520),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/images/galaxy.png', 'GET', '3xx', 1, 1454, 0),
('2025-12-19 20:33:00', 1, 'localhost', '/assets/js/star.js', 'GET', '2xx', 1, 1333, 26414),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 2, 1693, 4750),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 911, 0),
('2025-12-19 20:34:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 3, 1593, 0),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 2, 1213, 3889446),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 1, 685, 0),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/logim4?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '4xx', 1, 831, 0),
('2025-12-19 20:34:00', 2, 'ngosing.online', '/product?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '4xx', 1, 832, 0),
('2025-12-19 20:35:00', 2, 'ngosing.online', '/dangnhap?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '4xx', 1, 833, 0),
('2025-12-19 20:35:00', 2, 'ngosing.online', '/login?q=union%20select%20sleep(1),table_name%20from%20information_schema.tables%20limit%201', 'GET', '4xx', 1, 785, 0),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 2, 1213, 3583123),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 1, 685, 0),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 584, 0),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 1, 634, 42520),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '3xx', 1, 721, 0),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 567, 26414),
('2025-12-19 20:36:00', 2, 'ngosing.online', '/dangnhap?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '4xx', 1, 839, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/', 'GET', '2xx', 1, 775, 2375),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 911, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 2, 1062, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 1, 624, 523923),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '3xx', 2, 1342, 0),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '2xx', 1, 716, 2257940),
('2025-12-19 23:04:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '3xx', 1, 654, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/__captcha/callback', 'GET', '2xx', 1, 2653, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 2, 1995, 4750),
('2025-12-19 23:20:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 2, 1388, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 2, 1847, 929280),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 2, 1950, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 878, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '3xx', 1, 965, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '3xx', 2, 2030, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 1, 928, 42520),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '3xx', 1, 1015, 0),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 861, 26414),
('2025-12-19 23:20:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '3xx', 1, 948, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/', 'GET', '2xx', 1, 1621, 924),
('2025-12-20 11:52:00', 1, 'localhost', '/', 'GET', '3xx', 1, 1640, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/auth/login', 'GET', '2xx', 2, 3477, 2315),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/auth/login', 'POST', '3xx', 1, 1874, 62),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/css/style.css', 'GET', '2xx', 1, 1583, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 1, 1669, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/js/script.js', 'GET', '2xx', 1, 1568, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 1, 1655, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/admin/products', 'GET', '3xx', 1, 1698, 46),
('2025-12-20 11:52:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 1561, 0),
('2025-12-20 11:52:00', 1, 'localhost', '/favicon.ico', 'GET', '4xx', 1, 1605, 150),
('2025-12-20 11:52:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 1, 1611, 42520),
('2025-12-20 11:52:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 1546, 0),
('2025-12-20 11:53:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 1831, 1076),
('2025-12-20 11:53:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1787, 0),
('2025-12-20 11:53:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 2, 3604, 0),
('2025-12-20 11:53:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 2, 3576, 0),
('2025-12-20 12:15:00', 1, 'localhost', '/admin/auth/login?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHE', 'GET', '2xx', 1, 1676, 1076),
('2025-12-20 12:15:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 1, 1745, 0),
('2025-12-20 12:15:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 1, 1731, 0),
('2025-12-20 12:24:00', 1, 'localhost', '/__captcha/callback', 'GET', '2xx', 1, 2465, 0),
('2025-12-20 12:24:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20union%20select%20union%20select%20union%20sele\\%C6%B0', 'GET', '2xx', 1, 917, 1076),
('2025-12-20 12:24:00', 1, 'localhost', '/admin/css/style.css', 'GET', '2xx', 1, 878, 0),
('2025-12-20 12:24:00', 1, 'localhost', '/admin/js/script.js', 'GET', '2xx', 1, 863, 0),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/auth/login', 'POST', '3xx', 2, 3715, 188),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20union%20sele', 'GET', '2xx', 1, 1891, 1239),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20union%20sele', 'GET', '3xx', 1, 1891, 0),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 2, 3398, 0),
('2025-12-20 12:35:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 2, 3370, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/__captcha/callback', 'GET', '2xx', 1, 3262, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/admin/auth/login?q=union%20select%20union%20select', 'GET', '2xx', 1, 1656, 1076),
('2025-12-20 19:51:00', 1, 'localhost', '/admin/css/style.css', 'GET', '3xx', 1, 1703, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/admin/js/script.js', 'GET', '3xx', 1, 1689, 0),
('2025-12-20 19:51:00', 1, 'localhost', '/favicon.ico', 'GET', '4xx', 1, 1655, 150),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/', 'GET', '2xx', 1, 857, 2375),
('2025-12-21 00:11:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 1, 694, 0),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 2, 1538, 3583123),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 1, 846, 0),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 747, 0),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '2xx', 1, 795, 2257940),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 1, 797, 42520),
('2025-12-21 00:11:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 730, 26414),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/', 'GET', '2xx', 1, 834, 2375),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/__captcha/callback', 'GET', '2xx', 1, 2382, 0),
('2025-12-21 00:12:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 1, 652, 0),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 2, 1455, 3889446),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 1, 806, 0),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 705, 0),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '2xx', 1, 753, 2257940),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 2, 1597, 85040),
('2025-12-21 00:12:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 688, 26414),
('2025-12-21 00:13:00', 1, 'localhost', '/', 'GET', '2xx', 5, 5388, 4620),
('2025-12-21 00:13:00', 1, 'localhost', '/__captcha/callback', 'GET', '2xx', 1, 2391, 0),
('2025-12-21 00:13:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 4, 4043, 4712),
('2025-12-21 00:13:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 4, 4244, 170080),
('2025-12-21 00:13:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 4, 3982, 36),
('2025-12-21 00:14:00', 1, 'localhost', '/', 'GET', '2xx', 8, 7536, 7392),
('2025-12-21 00:14:00', 1, 'localhost', '/__captcha/callback', 'GET', '2xx', 1, 2476, 0),
('2025-12-21 00:14:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 8, 6196, 18848),
('2025-12-21 00:14:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 8, 6596, 340160),
('2025-12-21 00:14:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 8, 6076, 144),
('2025-12-21 00:15:00', 1, 'localhost', '/', 'GET', '2xx', 10, 9435, 9240),
('2025-12-21 00:15:00', 1, 'localhost', '/', 'GET', '3xx', 11, 10959, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 781, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 21, 18215, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 2, 1662, 85040),
('2025-12-21 00:15:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 19, 17450, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 3, 2298, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 16, 13624, 0),
('2025-12-21 00:15:00', 1, 'localhost', '/products', 'GET', '2xx', 1, 947, 1102),
('2025-12-21 00:16:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 'GET', '4xx', 1, 629, 187),
('2025-12-21 00:16:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 1, 867, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/', 'GET', '2xx', 1, 880, 2375),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/', 'GET', '3xx', 4, 3864, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 4, 2608, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 1, 704, 3506176),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 705, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '3xx', 3, 2376, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '2xx', 1, 753, 2257940),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '3xx', 3, 2526, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 1, 755, 42520),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '3xx', 3, 2526, 0),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 688, 26414),
('2025-12-21 00:16:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '3xx', 3, 2325, 0),
('2025-12-21 00:17:00', 1, 'localhost', '/', 'GET', '2xx', 1, 879, 924),
('2025-12-21 00:17:00', 1, 'localhost', '/', 'GET', '3xx', 4, 3998, 0),
('2025-12-21 00:17:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 5, 4335, 0),
('2025-12-21 00:17:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 5, 4590, 0),
('2025-12-21 00:17:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 5, 4255, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/', 'GET', '2xx', 2, 1760, 4750),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/', 'GET', '3xx', 6, 5796, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 7, 4564, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 1, 751, 371859),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 3, 2406, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 2, 1410, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '3xx', 5, 3960, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '3xx', 7, 5894, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 2, 1510, 85040),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '3xx', 6, 5052, 0),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 2, 1376, 52828),
('2025-12-21 00:17:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '3xx', 5, 3875, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/', 'GET', '2xx', 8, 7550, 4620),
('2025-12-21 00:19:00', 1, 'localhost', '/', 'GET', '3xx', 1, 995, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 10, 8652, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 10, 9162, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 10, 8492, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/products', 'GET', '2xx', 14, 13506, 0),
('2025-12-21 00:19:00', 1, 'localhost', '/products', 'GET', '3xx', 4, 4044, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/', 'GET', '2xx', 1, 880, 2375),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/', 'GET', '3xx', 97, 93702, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 14, 9128, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 2, 1606, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 705, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '3xx', 97, 76824, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '3xx', 98, 82516, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 1, 755, 42520),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '3xx', 98, 82516, 0),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 688, 26414),
('2025-12-21 00:19:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '3xx', 97, 75175, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/', 'GET', '2xx', 2, 1906, 1848),
('2025-12-21 00:20:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 12, 10556, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 12, 11168, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 12, 10364, 0),
('2025-12-21 00:20:00', 1, 'localhost', '/products', 'GET', '2xx', 46, 44302, 9918),
('2025-12-21 00:20:00', 1, 'localhost', '/products', 'GET', '3xx', 1, 1005, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/', 'GET', '2xx', 16, 15233, 2772),
('2025-12-21 00:22:00', 1, 'localhost', '/', 'GET', '3xx', 2, 1990, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 8, 6984, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 8, 7392, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 770, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 6, 5146, 0),
('2025-12-21 00:22:00', 1, 'localhost', '/products', 'GET', '2xx', 1, 887, 1102),
('2025-12-21 00:22:00', 1, 'localhost', '/products', 'GET', '3xx', 1, 1003, 0),
('2025-12-21 00:29:00', 1, 'localhost', '/', 'GET', '2xx', 1, 878, 924),
('2025-12-21 00:29:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 1035, 924),
('2025-12-21 00:29:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 2, 2226, 0),
('2025-12-21 00:29:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 1, 867, 0),
('2025-12-21 00:29:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 1, 918, 0),
('2025-12-21 00:29:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 1, 851, 0),
('2025-12-21 00:30:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1019, 0),
('2025-12-21 00:30:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 'GET', '4xx', 2, 1264, 374),
('2025-12-21 00:31:00', 1, 'localhost', '/__captcha/callback', 'GET', '2xx', 1, 2578, 0),
('2025-12-21 00:31:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 959, 924),
('2025-12-21 00:32:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1057, 0),
('2025-12-21 00:33:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1151, 0),
('2025-12-21 00:33:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 'GET', '4xx', 2, 1258, 374),
('2025-12-21 00:34:00', 2, 'ngosing.online', '/__captcha/callback', 'GET', '2xx', 1, 2569, 0),
('2025-12-21 00:34:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '2xx', 1, 965, 2375),
('2025-12-21 00:34:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 1, 652, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 3, 3371, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/.well-known/appspecific/com.chrome.devtools.json', 'GET', '4xx', 3, 1905, 374),
('2025-12-21 00:36:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 918, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 2, 2008, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 1, 968, 42520),
('2025-12-21 00:36:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 2, 2110, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 1, 903, 0),
('2025-12-21 00:36:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 2, 1976, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/?q=%27%20UN/**/ION%20SELECT%201%20FROM%20information_schema.tables%20WHERE%201=1%20or%201=1--%20SLEEP', 'GET', '3xx', 1, 1097, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 1, 652, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 1, 835, 3325587),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 836, 0),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '2xx', 1, 884, 2257940),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 1, 886, 42520),
('2025-12-21 00:36:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 1, 819, 26414),
('2025-12-21 00:48:00', 1, 'localhost', '/', 'GET', '2xx', 5, 4685, 4620),
('2025-12-21 00:48:00', 1, 'localhost', '/', 'GET', '3xx', 13, 12935, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/__captcha/callback', 'GET', '2xx', 1, 2434, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/css/style.css', 'GET', '2xx', 1, 785, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/css/style.css', 'GET', '3xx', 18, 15686, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/images/galaxy.png', 'GET', '2xx', 3, 2505, 127560),
('2025-12-21 00:48:00', 1, 'localhost', '/images/galaxy.png', 'GET', '3xx', 14, 12916, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/js/script.js', 'GET', '2xx', 3, 2310, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/js/script.js', 'GET', '3xx', 13, 11123, 0),
('2025-12-21 00:48:00', 1, 'localhost', '/products', 'GET', '2xx', 1, 951, 0),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/', 'GET', '2xx', 2, 1731, 4750),
('2025-12-21 19:33:00', 2, 'ngosing.online', '//ws', 'GET', '2xx', 2, 1372, 0),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 2, 1518, 4107411),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '2xx', 1, 732, 0),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/css/style.css', 'GET', '3xx', 3, 2487, 0),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/images/BGR3.png', 'GET', '2xx', 2, 1575, 4515880),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '2xx', 2, 1579, 85040),
('2025-12-21 19:33:00', 2, 'ngosing.online', '/assets/js/star.js', 'GET', '2xx', 2, 1445, 52828),
('2025-12-21 19:40:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '2xx', 1, 792, 2927763),
('2025-12-21 19:40:00', 2, 'ngosing.online', '/assets/audio/Song.mp3', 'GET', '3xx', 1, 845, 0),
('2025-12-21 19:40:00', 2, 'ngosing.online', '/assets/images/galaxy.png', 'GET', '3xx', 1, 884, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/', 'GET', '2xx', 265, 20405, 19875530),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kB_', 'GET', '2xx', 1, 1069, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kH4&sid=DgM49WH8tgVjUHtcAACX', 'POST', '4xx', 1, 1182, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kHA&sid=DgM49WH8tgVjUHtcAACX', 'GET', '2xx', 1, 1094, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-khL', 'GET', '2xx', 1, 1069, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-khX&sid=YTLYDi2MaNfLSOLeAACZ', 'POST', '4xx', 1, 1182, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-khY&sid=YTLYDi2MaNfLSOLeAACZ', 'GET', '2xx', 1, 1094, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kK-&sid=DgM49WH8tgVjUHtcAACX', 'POST', '4xx', 1, 1181, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-kmi&sid=YTLYDi2MaNfLSOLeAACZ', 'POST', '4xx', 1, 1181, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lAg&sid=Tp1yYWgXrsR3jt4LAACb', 'POST', '4xx', 1, 1182, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lAh&sid=Tp1yYWgXrsR3jt4LAACb', 'GET', '2xx', 1, 1094, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lAT', 'GET', '2xx', 1, 1069, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lfc', 'GET', '2xx', 1, 1069, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lFd&sid=Tp1yYWgXrsR3jt4LAACb', 'POST', '4xx', 1, 1181, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lfp&sid=xwkcjhBndpDwzu7yAACd', 'POST', '4xx', 1, 1182, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lfq&sid=xwkcjhBndpDwzu7yAACd', 'GET', '2xx', 1, 1094, 0),
('2025-12-21 19:56:00', 1, 'localhost', '/socket.io/?EIO=4&transport=polling&t=Pj0-lko&sid=xwkcjhBndpDwzu7yAACd', 'POST', '4xx', 1, 1181, 0);

-- --------------------------------------------------------

--
-- Table structure for table `request_minute_summary`
--

CREATE TABLE `request_minute_summary` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `timestamp` datetime NOT NULL,
  `domain_id` bigint(20) UNSIGNED NOT NULL,
  `total_requests` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `requests_2xx` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `requests_4xx` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `requests_5xx` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `total_bytes_in` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `total_bytes_out` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `peak_requests_min` int(10) UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Minute-level aggregated request summary (per domain)';

--
-- Dumping data for table `request_minute_summary`
--

INSERT INTO `request_minute_summary` (`id`, `timestamp`, `domain_id`, `total_requests`, `requests_2xx`, `requests_4xx`, `requests_5xx`, `total_bytes_in`, `total_bytes_out`, `peak_requests_min`) VALUES
(1, '2025-12-19 19:46:00', 1, 14, 6, 1, 0, 24668, 44696, 2),
(2, '2025-12-19 19:47:00', 1, 9, 4, 1, 0, 15231, 1329, 2),
(3, '2025-12-19 19:48:00', 1, 5, 1, 1, 0, 8762, 1534, 1),
(4, '2025-12-19 19:49:00', 1, 5, 2, 0, 0, 8729, 2377, 1),
(5, '2025-12-19 19:50:00', 1, 11, 5, 0, 0, 19447, 3076, 1),
(6, '2025-12-19 19:52:00', 1, 13, 5, 0, 0, 22695, 44368, 4),
(7, '2025-12-19 19:53:00', 1, 4, 4, 0, 0, 6442, 43622, 1),
(8, '2025-12-19 19:55:00', 1, 18, 1, 0, 0, 31487, 1102, 5),
(9, '2025-12-19 19:56:00', 1, 1, 0, 0, 0, 1805, 0, 1),
(10, '2025-12-19 20:08:00', 1, 1, 0, 1, 0, 1632, 160, 1),
(11, '2025-12-19 20:09:00', 1, 7, 4, 1, 0, 11711, 43631, 1),
(12, '2025-12-19 20:22:00', 1, 7, 5, 1, 0, 6468, 44555, 1),
(13, '2025-12-19 20:23:00', 1, 9, 8, 0, 0, 6328, 86888, 2),
(14, '2025-12-19 20:24:00', 1, 8, 1, 0, 0, 6596, 924, 2),
(15, '2025-12-19 20:31:00', 2, 7, 5, 2, 0, 4479, 2349787, 1),
(16, '2025-12-19 20:33:00', 1, 12, 10, 0, 0, 16574, 6189557, 2),
(17, '2025-12-19 20:34:00', 2, 11, 7, 2, 0, 7758, 3894196, 3),
(18, '2025-12-19 20:35:00', 2, 2, 0, 2, 0, 1618, 0, 1),
(19, '2025-12-19 20:36:00', 2, 8, 5, 1, 0, 5243, 3652057, 2),
(20, '2025-12-19 23:04:00', 2, 9, 5, 0, 0, 6084, 2784238, 2),
(21, '2025-12-19 23:20:00', 2, 17, 10, 0, 0, 17458, 1002964, 2),
(22, '2025-12-20 11:52:00', 1, 14, 8, 1, 0, 23108, 46017, 2),
(23, '2025-12-20 11:53:00', 1, 6, 1, 0, 0, 10798, 1076, 2),
(24, '2025-12-20 12:15:00', 1, 3, 1, 0, 0, 5152, 1076, 1),
(25, '2025-12-20 12:24:00', 1, 4, 4, 0, 0, 5123, 1076, 1),
(26, '2025-12-20 12:35:00', 1, 8, 1, 0, 0, 14265, 1427, 2),
(27, '2025-12-20 19:51:00', 1, 5, 2, 1, 0, 9965, 1226, 1),
(28, '2025-12-21 00:11:00', 2, 9, 8, 0, 0, 7004, 5912372, 2),
(29, '2025-12-21 00:12:00', 2, 11, 10, 0, 0, 9872, 6261215, 2),
(30, '2025-12-21 00:13:00', 1, 18, 18, 0, 0, 20048, 179448, 3),
(31, '2025-12-21 00:14:00', 1, 33, 33, 0, 0, 28880, 366544, 8),
(32, '2025-12-21 00:15:00', 1, 84, 17, 0, 0, 75371, 95382, 21),
(33, '2025-12-21 00:16:00', 2, 26, 10, 0, 0, 20710, 5835425, 4),
(34, '2025-12-21 00:16:00', 1, 2, 0, 1, 0, 1496, 187, 1),
(35, '2025-12-21 00:17:00', 2, 48, 16, 0, 0, 38354, 514477, 7),
(36, '2025-12-21 00:17:00', 1, 20, 1, 0, 0, 18057, 924, 5),
(37, '2025-12-21 00:19:00', 2, 507, 18, 0, 0, 424495, 71309, 98),
(38, '2025-12-21 00:19:00', 1, 57, 22, 0, 0, 52401, 4620, 14),
(39, '2025-12-21 00:20:00', 1, 85, 48, 0, 0, 79301, 11766, 39),
(40, '2025-12-21 00:22:00', 1, 43, 18, 0, 0, 39405, 3874, 14),
(41, '2025-12-21 00:29:00', 1, 7, 2, 0, 0, 6775, 1848, 2),
(42, '2025-12-21 00:30:00', 1, 3, 0, 2, 0, 2283, 374, 2),
(43, '2025-12-21 00:31:00', 1, 2, 2, 0, 0, 3537, 924, 1),
(44, '2025-12-21 00:32:00', 1, 1, 0, 0, 0, 1057, 0, 1),
(45, '2025-12-21 00:33:00', 1, 3, 0, 2, 0, 2409, 374, 2),
(46, '2025-12-21 00:34:00', 2, 3, 3, 0, 0, 4186, 2375, 1),
(47, '2025-12-21 00:36:00', 1, 15, 3, 3, 0, 14159, 42894, 3),
(48, '2025-12-21 00:36:00', 2, 7, 6, 0, 0, 6009, 5652461, 1),
(49, '2025-12-21 00:48:00', 1, 72, 14, 0, 0, 66330, 132180, 18),
(50, '2025-12-21 19:33:00', 2, 16, 13, 0, 0, 12439, 8765909, 3),
(51, '2025-12-21 19:40:00', 2, 3, 1, 0, 0, 2521, 2927763, 1),
(52, '2025-12-21 19:56:00', 1, 281, 273, 8, 0, 38509, 19875530, 254);

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `username` varchar(64) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User accounts & roles';

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password_hash`) VALUES
(1, 'user01', 'user01@gmail.com', '123');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `blacklist`
--
ALTER TABLE `blacklist`
  ADD PRIMARY KEY (`ip`),
  ADD KEY `idx_created_at` (`created_at`);

--
-- Indexes for table `cache_stats_minute`
--
ALTER TABLE `cache_stats_minute`
  ADD PRIMARY KEY (`ts_minute`,`domain_id`,`host`,`route_bucket`),
  ADD KEY `idx_csm_domain_time` (`domain_id`,`ts_minute`),
  ADD KEY `idx_csm_timestamp` (`ts_minute`);

--
-- Indexes for table `domains`
--
ALTER TABLE `domains`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_domains_user_domain` (`user_id`,`domain`);

--
-- Indexes for table `domain_origins`
--
ALTER TABLE `domain_origins`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_origins_domain` (`domain_id`);

--
-- Indexes for table `metrics_minute`
--
ALTER TABLE `metrics_minute`
  ADD PRIMARY KEY (`ts_minute`,`domain_id`,`host`,`route_bucket`,`method`,`status_class`),
  ADD KEY `idx_mm_domain_time` (`domain_id`,`ts_minute`),
  ADD KEY `idx_mm_route` (`domain_id`,`route_bucket`),
  ADD KEY `idx_mm_timestamp` (`ts_minute`);

--
-- Indexes for table `request_minute_summary`
--
ALTER TABLE `request_minute_summary`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_timestamp_domain` (`timestamp`,`domain_id`),
  ADD KEY `idx_domain_time` (`domain_id`,`timestamp`),
  ADD KEY `idx_timestamp_desc` (`timestamp`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `domains`
--
ALTER TABLE `domains`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `domain_origins`
--
ALTER TABLE `domain_origins`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `request_minute_summary`
--
ALTER TABLE `request_minute_summary`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=53;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `cache_stats_minute`
--
ALTER TABLE `cache_stats_minute`
  ADD CONSTRAINT `fk_cache_stats_domain` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `domains`
--
ALTER TABLE `domains`
  ADD CONSTRAINT `fk_domains_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `domain_origins`
--
ALTER TABLE `domain_origins`
  ADD CONSTRAINT `fk_origins_domain` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `metrics_minute`
--
ALTER TABLE `metrics_minute`
  ADD CONSTRAINT `fk_metrics_domain` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `request_minute_summary`
--
ALTER TABLE `request_minute_summary`
  ADD CONSTRAINT `fk_rms_domain` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
