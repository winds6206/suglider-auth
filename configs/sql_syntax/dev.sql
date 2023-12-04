CREATE DATABASE IF NOT EXISTS suglider;

USE suglider;

CREATE TABLE IF NOT EXISTS user_info (
    user_id BINARY(16) NOT NULL,
    username VARCHAR(256) DEFAULT NULL,
    password VARCHAR(256),
    last_name VARCHAR(10),
    first_name VARCHAR(10),
    phone_number VARCHAR(10) DEFAULT NULL,
    mail VARCHAR(256) NOT NULL,
    mail_verified INT UNSIGNED NOT NULL DEFAULT 0,
    address VARCHAR(256),
    mail_otp_enabled BOOL DEFAULT false,
    sms_otp_enabled BOOL DEFAULT false,
    password_expire_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id),
    UNIQUE(username),
    UNIQUE(phone_number),
    UNIQUE(mail));

CREATE TABLE IF NOT EXISTS aes (
    user_id BINARY(16) NOT NULL,
    aes_encrypt_key VARCHAR(32) NOT NULL,
    PRIMARY KEY(user_id));

CREATE TABLE IF NOT EXISTS rsa (
    user_id BINARY(16) NOT NULL,
    rsa_public_key TEXT NOT NULL,
    rsa_private_key TEXT NOT NULL,
    PRIMARY KEY(user_id));

CREATE TABLE IF NOT EXISTS suglider.totp (
    user_id BINARY(16) NOT NULL,
    totp_enabled BOOL DEFAULT false,
    totp_verified BOOL DEFAULT false,
    totp_secret VARCHAR(256) NOT NULL,
    totp_url VARCHAR(256) NOT NULL,
    PRIMARY KEY(user_id),
    FOREIGN KEY(user_id) REFERENCES user_info(user_id) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS `casbin_policies` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `p_type` VARCHAR(32) NOT NULL DEFAULT '',
    `v0` VARCHAR(255) NOT NULL DEFAULT '',
    `v1` VARCHAR(255) NOT NULL DEFAULT '',
    `v2` VARCHAR(255) NOT NULL DEFAULT '',
    `v3` VARCHAR(255) NOT NULL DEFAULT '',
    `v4` VARCHAR(255) NOT NULL DEFAULT '',
    `v5` VARCHAR(255) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
