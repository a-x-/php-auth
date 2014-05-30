CREATE DATABASE IF NOT EXISTS login;

CREATE TABLE user
(
  user_id INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
  user_name VARCHAR(64) NOT NULL,
  user_password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(64),
  user_active TINYINT DEFAULT 0 NOT NULL,
  user_activation_hash VARCHAR(40),
  user_password_reset_hash CHAR(40),
  user_password_reset_timestamp BIGINT,
  user_rememberme_token VARCHAR(64),
  user_failed_logins TINYINT DEFAULT 0 NOT NULL,
  user_last_failed_login INT,
  user_registration_datetime DATETIME DEFAULT '0000-00-00 00:00:00' NOT NULL,
  user_registration_ip VARCHAR(39) DEFAULT '0.0.0.0' NOT NULL,
  user_auto_signin_sequence LINESTRING NOT NULL,
 PRIMARY KEY (user_id),
 UNIQUE KEY user_email (email)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='user data';

CREATE TABLE user_connections
(
  id BIGINT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  user_rememberme_token VARCHAR(64),
  user_last_visit DATETIME DEFAULT '0000-00-00 00:00:00' NOT NULL,
  user_last_visit_agent LONGTEXT,
  user_login_ip VARCHAR(39) DEFAULT '0.0.0.0' NOT NULL,
  user_login_datetime DATETIME DEFAULT '0000-00-00 00:00:00' NOT NULL,
  user_login_agent LONGTEXT
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='authenticated user data';
