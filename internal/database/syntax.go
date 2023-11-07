package database

import (
	"database/sql"
	"context"
	"time"
	"fmt"
	"log/slog"
	"suglider-auth/configs"
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

func UserSignUp(username, password, mail, address string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "INSERT INTO suglider.user_info(user_id, username, password, mail, address) VALUES (UNHEX(REPLACE(UUID(), '-', '')),?,?,?,?)"
	_, err = DataBase.ExecContext(ctx, sqlStr, username, password, mail, address)
	return err
}

func UserDelete(username, mail string) (result sql.Result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "DELETE FROM suglider.user_info WHERE username=? AND mail=?"
	result, err = DataBase.ExecContext(ctx, sqlStr, username, mail)
	return result, err
}

func UserDeleteByUUID(user_id, username, mail string) (result sql.Result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	// UNHEX(?) can convert user_id to binary(16)
	sqlStr := "DELETE FROM suglider.user_info WHERE user_id=UNHEX(?) AND username=? AND mail=?"
	result, err = DataBase.ExecContext(ctx, sqlStr,user_id ,username, mail)
	return result, err
}

func UserLogin(username string) (userInfo UserDBInfo ,err error){
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userInfo, "SELECT username, password, LOWER(HEX(user_id)) AS user_id FROM suglider.user_info WHERE username=?", username)

	return userInfo, err
}

func TotpStoreSecret(user_id, username, totp_secret, totp_url string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "INSERT INTO suglider.totp(user_id, username, totp_secret, totp_url) VALUES (UNHEX(?),?,?,?)"
	_, err = DataBase.ExecContext(ctx, sqlStr, user_id, username, totp_secret, totp_url)
	return err
}

func TotpUpdateSecret(user_id, username, totp_secret, totp_url string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " + 
			"SET totp_secret = ?, totp_url = ? " +
			"WHERE user_id = UNHEX(?) AND username = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totp_secret, totp_url, user_id, username)
	return err
}

func TotpUserCheck(user_id, username string) (rowCount int, err error) {
	var count int
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT COUNT(*) FROM suglider.totp WHERE user_id=UNHEX(?) AND username=?"
	err = DataBase.GetContext(ctx, &count, sqlStr, user_id, username)
	return count, err
}

func TotpUserData(user_id, username string) (totpUserInfo TotpUserInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "SELECT * FROM suglider.totp WHERE user_id=UNHEX(?) AND username=?"
	err = DataBase.GetContext(ctx, &totpUserInfo, sqlStr, user_id, username)
	return totpUserInfo, err
}

func TotpUpdateVerify(user_id, username string, totp_enabled, totp_verified bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " + 
			"SET totp_enabled = ?, totp_verified = ? " +
			"WHERE user_id = UNHEX(?) AND username = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totp_enabled, totp_verified, user_id, username)
	return err
}

func TotpUpdateEnabled(user_id, username string, totp_enabled bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	sqlStr := "UPDATE suglider.totp " + 
			"SET totp_enabled = ? " +
			"WHERE user_id = UNHEX(?) AND username = ?"
	_, err = DataBase.ExecContext(ctx, sqlStr, totp_enabled, user_id, username)
	return err
}

func LookupUserID(username string) (userIDInfo UserIDInfo ,err error){
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeOut)
	defer cancel()

	err = DataBase.GetContext(ctx, &userIDInfo, "SELECT LOWER(HEX(user_id)) AS user_id FROM suglider.user_info WHERE username=?", username)
	return userIDInfo, err
}