package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"suglider-auth/configs"
	"time"
)

var dbTimeOut time.Duration

func init() {
	var DatabaseConfig = configs.ApplicationConfig.Database
	var err error

	dbTimeOut, err = time.ParseDuration(DatabaseConfig.Timeout)

	if err != nil {
		errorMessage := fmt.Sprintf("DB timeout string convert to duration failed: %v", err)
		slog.Error(errorMessage)

		panic(err)
	}
}

func UserSignUp(userName, password, comfirmPassword, mail, address string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "INSERT INTO suglider.user_info(user_id, username, password, comfirm_pwd, mail, address, password_expire_date) VALUES (UNHEX(REPLACE(UUID(), '-', '')),?,?,?,?,?,DATE_ADD(CURRENT_DATE, INTERVAL 90 DAY))"
	_, err = DataBase.ExecContext(ctx, sqlStr, userName, password, comfirmPassword, mail, address)
	return err
}

func UserDelete(userName, mail string) (result sql.Result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "DELETE FROM suglider.user_info WHERE username=? AND mail=?"
	result, err = DataBase.ExecContext(ctx, sqlStr, userName, mail)
	return result, err
}

func UserDeleteByUUID(userID, userName, mail string) (result sql.Result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	// UNHEX(?) can convert user_id to binary(16)
	sqlStr := "DELETE FROM suglider.user_info WHERE user_id=UNHEX(?) AND username=? AND mail=?"
	result, err = DataBase.ExecContext(ctx, sqlStr, userID, userName, mail)
	return result, err
}

func UserLogin(userName string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT username, password, LOWER(HEX(user_id)) AS user_id FROM suglider.user_info WHERE username=?", userName)

	return userInfo, err
}

func PasswordExpire(userName string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT username, password_expire_date FROM suglider.user_info WHERE username=?", userName)

	return userInfo, err
}

func PasswordExtension(userName string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.user_info " +
		"SET password_expire_date = DATE_ADD(CURRENT_DATE, INTERVAL 90 DAY)" +
		"WHERE user_info.username = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, userName)
	return err
}

func UserSetMailVerified(ctx context.Context, mail string) error {
	statmt := fmt.Sprintf("UPDATE %s SET mail_verified = ? WHERE %s = ?", "user_info", "mail")
	if _, err := DataBase.ExecContext(ctx, statmt, 1, mail); err != nil {
		return err
	}
	return nil
}

func UserMailIsVerified(ctx context.Context, mail string) (bool, error) {
	var isVerified int
	query := fmt.Sprintf("SELECT mail_verified FROM %s WHERE %s = ?", "user_info", "mail")
	row := DataBase.QueryRowContext(ctx, query, mail)
	err := row.Scan(&isVerified)
	if err != nil {
		slog.Error(err.Error())
	}
	if isVerified == 1 {
		return true, err
	}
	return false, err
}

func UserResetPassword(ctx context.Context, mail, password string) error {
	statmt := fmt.Sprintf("UPDATE %s SET password = ?, password_expire_date = DATE_ADD(CURRENT_DATE, INTERVAL 90 DAY) WHERE %s = ?", "user_info", "mail")
	if _, err := DataBase.ExecContext(ctx, statmt, password, mail); err != nil {
		return err
	}
	return nil
}

func UserGetNameByMail(ctx context.Context, mail string) (string, error) {
	var name string
	query := fmt.Sprintf("SELECT username FROM %s WHERE %s = ?", "user_info", "mail")
	row := DataBase.QueryRowContext(ctx, query, mail)
	err := row.Scan(&name)
	if err != nil {
		slog.Error(err.Error())
		return "", err
	}
	return name, nil
}

func TotpStoreSecret(userID, totpSecret, totpURL string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "INSERT INTO suglider.totp(user_id, totp_secret, totp_url) VALUES (UNHEX(?),?,?)"
	_, err = DataBase.ExecContext(ctx, sqlStr, userID, totpSecret, totpURL)
	return err
}

func TotpUpdateSecret(userName, totpSecret, totpURL string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " +
		"JOIN suglider.user_info ON user_info.user_id = totp.user_id " +
		"SET totp_secret = ?, totp_url = ? " +
		"WHERE user_info.username = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totpSecret, totpURL, userName)
	return err
}

func TotpUserCheck(userID string) (rowCount int, err error) {
	var count int
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT COUNT(*) FROM suglider.totp WHERE user_id=UNHEX(?)"
	err = DataBase.GetContext(ctx, &count, sqlStr, userID)
	return count, err
}

func TotpUserData(userName string) (totpUserInfo TotpUserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT totp.user_id, totp.totp_enabled, totp_verified, totp.totp_secret, totp_url " +
		"FROM suglider.user_info " +
		"INNER JOIN suglider.totp ON user_info.user_id = totp.user_id " +
		"WHERE user_info.username=?"
	err = DataBase.GetContext(ctx, &totpUserInfo, sqlStr, userName)
	return totpUserInfo, err
}

func TotpUpdateVerify(userName string, totpEnabled, totpVerified bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " +
		"JOIN suglider.user_info ON user_info.user_id = totp.user_id " +
		"SET totp_enabled = ?, totp_verified = ? " +
		"WHERE username = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totpEnabled, totpVerified, userName)
	return err
}

func TotpUpdateEnabled(userName string, totpEnabled bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " +
		"JOIN suglider.user_info ON user_info.user_id = totp.user_id " +
		"SET totp_enabled = ? " +
		"WHERE username = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totpEnabled, userName)
	return err
}

func LookupUserID(userName string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT LOWER(HEX(user_id)) AS user_id FROM suglider.user_info WHERE username=?", userName)
	return userInfo, err
}

func CheckUsername(userName string) (rowCount int, err error) {
	var count int
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT COUNT(*) FROM suglider.user_info WHERE username=?"
	err = DataBase.GetContext(ctx, &count, sqlStr, userName)
	return count, err
}

func CheckMail(mail string) (rowCount int, err error) {
	var count int
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT COUNT(*) FROM suglider.user_info WHERE mail=?"
	err = DataBase.GetContext(ctx, &count, sqlStr, mail)
	return count, err
}

func MailOTPupdateEnabled(userName string, mailOTPenabled bool) (int64, int64, error) {
	var errCode int64
	errCode = 0

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.user_info " +
		"SET mail_otp_enabled = ? " +
		"WHERE username = ?"
	result, err := DataBase.ExecContext(ctx, sqlStr, mailOTPenabled, userName)
	if err != nil {
		errCode = 1002
		return 0, errCode, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		errCode = 1049
		return 0, errCode, err
	}

	return rowsAffected, errCode, err
}

func GetUserInfo(userName string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT first_name, mail " +
		"FROM suglider.user_info " +
		"WHERE user_info.username=?"
	err = DataBase.GetContext(ctx, &userInfo, sqlStr, userName)
	return userInfo, err
}

func UserTwoFactorAuth(userName string) (userTwoFactorAuthInfo UserTwoFactorAuthInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT totp.user_id, user_info.username, totp.totp_enabled, user_info.mail_otp_enabled, user_info.sms_otp_enabled " +
		"FROM suglider.user_info " +
		"LEFT JOIN suglider.totp ON user_info.user_id = totp.user_id " +
		"WHERE user_info.username=?"
	err = DataBase.GetContext(ctx, &userTwoFactorAuthInfo, sqlStr, userName)
	return userTwoFactorAuthInfo, err
}
