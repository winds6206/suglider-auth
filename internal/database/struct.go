package database

import "database/sql"

type UserInfo struct {
	Username           string `db:"username"`
	Password           string `db:"password"`
	UserID             string `db:"user_id"`
	Mail               string `db:"mail"`
	FirstName          string `db:"first_name"`
	PasswordExpireDate string `db:"password_expire_date"`
}

type TotpUserInfo struct {
	UserID       string `db:"user_id"`
	TotpEnabled  bool   `db:"totp_enabled"`
	TotpVerified bool   `db:"totp_verified"`
	TotpSecret   string `db:"totp_secret"`
	TotpURL      string `db:"totp_url"`
}

type UserTwoFactorAuthInfo struct {
	UserName       string         `db:"username"`
	UserID         sql.NullString `db:"user_id"`
	TotpEnabled    sql.NullBool   `db:"totp_enabled"`
	MailOTPenabled bool           `db:"mail_otp_enabled"`
	SmsOTPenabled  bool           `db:"sms_otp_enabled"`
}
