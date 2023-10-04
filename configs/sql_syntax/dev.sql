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