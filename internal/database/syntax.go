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

func UserSignUp(mail, password string, userName, firstName, lastName, phoneNumber *string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlUserInfo := "INSERT INTO suglider.user_info(user_id, mail, password, username, first_name, last_name, phone_number, password_expire_date) " +
		"VALUES (UNHEX(REPLACE(UUID(), '-', '')),?,?,?,?,?,?,DATE_ADD(CURRENT_DATE, INTERVAL 90 DAY))"
	_, err = DataBase.ExecContext(ctx, sqlUserInfo, mail, password, userName, firstName, lastName, phoneNumber)
	if err != nil {
		return err
	}

	return nil
}

func UpdateSignUp(mail, password string, userName, firstName, lastName, phoneNumber *string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.user_info " +
		"SET password = ?, username = ?, first_name = ?, last_name = ?, phone_number = ?, password_expire_date = DATE_ADD(CURRENT_DATE, INTERVAL 90 DAY), password_updated_at = CURRENT_TIMESTAMP " +
		"WHERE user_info.mail = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, password, userName, firstName, lastName, phoneNumber, mail)
	if err != nil {
		return err
	}

	return nil
}

func UserDelete(userName, mail string) (result sql.Result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "DELETE FROM suglider.user_info " +
		"WHERE username=? AND mail=?"
	result, err = DataBase.ExecContext(ctx, sqlStr, userName, mail)
	return result, err
}

func UserDeleteByMail(mail string) (result sql.Result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "DELETE FROM suglider.user_info " +
		"WHERE mail=?"
	result, err = DataBase.ExecContext(ctx, sqlStr, mail)
	return result, err
}

// func UserDeleteByUUID(userID, userName, mail string) (result sql.Result, err error) {
// 	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
// 	defer cancel()

// 	// UNHEX(?) can convert user_id to binary(16)
// 	sqlStr := "DELETE FROM suglider.user_info " +
// 		"WHERE user_id=UNHEX(?) AND username=? AND mail=?"
// 	result, err = DataBase.ExecContext(ctx, sqlStr, userID, userName, mail)
// 	return result, err
// }

func GetPasswordByUserName(userName string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT username, mail, password FROM suglider.user_info WHERE username=?", userName)

	return userInfo, err
}

func GetPasswordByMail(mail string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT mail, password FROM suglider.user_info WHERE mail=?", mail)

	return userInfo, err
}

func GetPasswordExpireByMail(mail string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT mail, password_expire_date FROM suglider.user_info WHERE mail=?", mail)

	return userInfo, err
}

func PasswordExtensionByMail(mail string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.user_info " +
		"SET password_expire_date = DATE_ADD(CURRENT_DATE, INTERVAL 90 DAY)" +
		"WHERE user_info.mail = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, mail)
	if err != nil {
		return err
	}

	return nil
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
	statmt := fmt.Sprintf("UPDATE %s SET password = ?, password_expire_date = DATE_ADD(CURRENT_DATE, INTERVAL 90 DAY, password_updated_at = CURRENT_TIMESTAMP) WHERE %s = ?", "user_info", "mail")
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

	sqlStr := "INSERT INTO suglider.totp(user_id, totp_secret, totp_url) " +
		"VALUES (UNHEX(?),?,?)"
	_, err = DataBase.ExecContext(ctx, sqlStr, userID, totpSecret, totpURL)
	if err != nil {
		return err
	}

	return nil
}

func TotpUpdateSecret(mail, totpSecret, totpURL string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " +
		"JOIN suglider.user_info ON user_info.user_id = totp.user_id " +
		"SET totp_secret = ?, totp_url = ? " +
		"WHERE user_info.mail = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totpSecret, totpURL, mail)
	if err != nil {
		return err
	}

	return nil
}

func TotpUserCheck(userID string) (rowCount int, err error) {
	var count int
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT COUNT(*) " +
		"FROM suglider.totp " +
		"WHERE user_id=UNHEX(?)"
	err = DataBase.GetContext(ctx, &count, sqlStr, userID)
	return count, err
}

func TotpUserData(mail string) (totpUserInfo TotpUserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT totp.user_id, totp.totp_enabled, totp_verified, totp.totp_secret, totp_url " +
		"FROM suglider.user_info " +
		"INNER JOIN suglider.totp ON user_info.user_id = totp.user_id " +
		"WHERE user_info.mail=?"
	err = DataBase.GetContext(ctx, &totpUserInfo, sqlStr, mail)
	return totpUserInfo, err
}

func TotpUpdateVerify(mail string, totpEnabled, totpVerified bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " +
		"JOIN suglider.user_info ON user_info.user_id = totp.user_id " +
		"SET totp_enabled = ?, totp_verified = ? " +
		"WHERE mail = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totpEnabled, totpVerified, mail)
	if err != nil {
		return err
	}

	return nil
}

func TotpUpdateEnabled(mail string, totpEnabled bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " +
		"JOIN suglider.user_info ON user_info.user_id = totp.user_id " +
		"SET totp_enabled = ? " +
		"WHERE mail = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totpEnabled, mail)
	if err != nil {
		return err
	}

	return nil
}

func LookupUserID(mail string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT LOWER(HEX(user_id)) AS user_id FROM suglider.user_info WHERE mail=?", mail)
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

func CheckMailExists(mail string) (rowCount int, err error) {
	var count int
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT COUNT(*) FROM suglider.user_info WHERE mail=?"
	err = DataBase.GetContext(ctx, &count, sqlStr, mail)
	return count, err
}

func MailOTPUpdateEnabled(mail string, mailOTPEnabled bool) (int64, int64, error) {
	var errCode int64
	errCode = 0

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.user_info " +
		"SET mail_otp_enabled = ? " +
		"WHERE mail = ?"
	result, err := DataBase.ExecContext(ctx, sqlStr, mailOTPEnabled, mail)
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

func GetUserInfo(mail string) (userInfo UserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT first_name, username, mail " +
		"FROM suglider.user_info " +
		"WHERE user_info.mail=?"
	err = DataBase.GetContext(ctx, &userInfo, sqlStr, mail)
	return userInfo, err
}

func GetTwoFactorAuthByUserName(userName string) (userTwoFactorAuthInfo UserTwoFactorAuthInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT totp.user_id, user_info.username ,user_info.mail, totp.totp_enabled, user_info.mail_otp_enabled, user_info.sms_otp_enabled " +
		"FROM suglider.user_info " +
		"LEFT JOIN suglider.totp ON user_info.user_id = totp.user_id " +
		"WHERE user_info.username=?"
	err = DataBase.GetContext(ctx, &userTwoFactorAuthInfo, sqlStr, userName)
	return userTwoFactorAuthInfo, err
}

func GetTwoFactorAuthByMail(mail string) (userTwoFactorAuthInfo UserTwoFactorAuthInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT totp.user_id, user_info.username ,user_info.mail, totp.totp_enabled, user_info.mail_otp_enabled, user_info.sms_otp_enabled " +
		"FROM suglider.user_info " +
		"LEFT JOIN suglider.totp ON user_info.user_id = totp.user_id " +
		"WHERE user_info.mail=?"
	err = DataBase.GetContext(ctx, &userTwoFactorAuthInfo, sqlStr, mail)
	return userTwoFactorAuthInfo, err
}

func OAuthSignUp(mail, firstName, lastName string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "INSERT INTO suglider.user_info(user_id, mail, first_name, last_name) " +
		"VALUES (UNHEX(REPLACE(UUID(), '-', '')),?,?,?)"
	_, err = DataBase.ExecContext(ctx, sqlStr, mail, firstName, lastName)
	if err != nil {
		return err
	}

	return nil
}

func InsertPersonalInfo(user_id string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "INSERT INTO suglider.personal_info(user_id) VALUES (UNHEX(?))"
	_, err = DataBase.ExecContext(ctx, sqlStr, user_id)
	if err != nil {
		return err
	}

	return nil
}

func UpdatePersonalInfoByMail(mail string, userName, lastName, firstName, phoneNumber, address, birthday, sex, bloodType *string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.user_info " +
		"JOIN suglider.personal_info ON user_info.user_id = personal_info.user_id " +
		"SET user_info.username = ?, user_info.last_name = ?, user_info.first_name = ?, " +
		"user_info.phone_number = ?, personal_info.address = ?, personal_info.birthday = ?, " +
		"personal_info.sex = ?, personal_info.blood_type = ? " +
		"WHERE user_info.mail = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, userName, lastName, firstName, phoneNumber, address, birthday, sex, bloodType, mail)
	if err != nil {
		return err
	}

	return nil
}
