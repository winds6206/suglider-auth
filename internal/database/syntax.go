package database

import (
	"database/sql"
)

func UserSignUp(username, password, mail, address string) (err error) {
	sqlStr := "INSERT INTO suglider.user_info(user_id, username, password, mail, address) VALUES (UNHEX(REPLACE(UUID(), '-', '')),?,?,?,?)"
	_, err = DataBase.Exec(sqlStr, username, password, mail, address)
	return err
}

func UserDelete(username, mail string) (result sql.Result, err error) {
	sqlStr := "DELETE FROM suglider.user_info WHERE username=? AND mail=?"
	result, err = DataBase.Exec(sqlStr, username, mail)
	return result, err
}

func UserDeleteByUUID(user_id, username, mail string) (result sql.Result, err error) {

	// UNHEX(?) can convert user_id to binary(16)
	sqlStr := "DELETE FROM suglider.user_info WHERE user_id=UNHEX(?) AND username=? AND mail=?"
	result, err = DataBase.Exec(sqlStr,user_id ,username, mail)
	return result, err
}

func UserLogin(username string) (userInfo UserDBInfo ,err error){
	err = DataBase.Get(&userInfo, "SELECT username, password FROM suglider.user_info WHERE username=?", username)
	return userInfo, err
}