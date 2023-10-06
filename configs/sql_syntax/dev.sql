CREATE DATABASE IF NOT EXISTS suglider;

USE suglider;

CREATE TABLE IF NOT EXISTS user_info (
    user_id BINARY(16) NOT NULL,
    username VARCHAR(256) NOT NULL,
    password VARCHAR(256) NOT NULL,
    mail VARCHAR(256) NOT NULL,
    address VARCHAR(256) NOT NULL,
    PRIMARY KEY(user_id),
    UNIQUE(username),
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
