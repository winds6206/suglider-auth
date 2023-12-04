package database

import "database/sql"

type UserInfo struct {
	Username           sql.NullString `db:"username"`
	UserID             string         `db:"user_id"`
	Mail               string         `db:"mail"`
	Password           sql.NullString `db:"password"`
	FirstName          sql.NullString `db:"first_name"`
	PasswordExpireDate string         `db:"password_expire_date"`
}

type TotpUserInfo struct {
	UserID       string `db:"user_id"`
	TotpEnabled  bool   `db:"totp_enabled"`
	TotpVerified bool   `db:"totp_verified"`
	TotpSecret   string `db:"totp_secret"`
	TotpURL      string `db:"totp_url"`
}

type UserTwoFactorAuthInfo struct {
	Mail           string         `db:"mail"`
	UserName       sql.NullString `db:"username"`
	UserID         sql.NullString `db:"user_id"`
	TotpEnabled    sql.NullBool   `db:"totp_enabled"`
	MailOTPEnabled bool           `db:"mail_otp_enabled"`
	SmsOTPEnabled  bool           `db:"sms_otp_enabled"`
}
