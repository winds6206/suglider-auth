package database

type UserDBInfo struct {
	Username           string `db:"username"`
	Password           string `db:"password"`
	UserID             string `db:"user_id"`
	PasswordExpireDate string `db:"password_expire_date"`
}

type UserIDInfo struct {
	UserID string `db:"user_id"`
}

type TotpUserInfo struct {
	UserID       string `db:"user_id"`
	TotpEnabled  bool   `db:"totp_enabled"`
	TotpVerified bool   `db:"totp_verified"`
	TotpSecret   string `db:"totp_secret"`
	TotpURL      string `db:"totp_url"`
}

type UserMail struct {
	Mail string `db:"mail"`
}
