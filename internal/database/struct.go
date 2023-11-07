package database

type UserDBInfo struct {
	Username string `db:"username"`
	Password string `db:"password"`
    UserID   string `db:"user_id"`
}

type UserIDInfo struct {
	UserID string `db:"user_id"`
}

type TotpUserInfo struct {
    UserID       string `db:"user_id"`
    Username     string `db:"username"`
    TotpEnabled  bool   `db:"totp_enabled"`
    TotpVerified bool   `db:"totp_verified"`
    TotpSecret   string `db:"totp_secret"`
    TotpURL      string `db:"totp_url"`
}
