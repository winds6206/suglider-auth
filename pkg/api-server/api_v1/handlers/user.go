package handlers

import (
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	mariadb "suglider-auth/internal/database/connect"
	"suglider-auth/pkg/encrypt"

)

type userSignUp struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Mail     string `json:"mail" binding:"required"`
	Address  string `json:"address" binding:"required"`
}

type userDelete struct {
	User_id  string `json:"user_id"`
	Username string `json:"username" binding:"required"`
	Mail     string `json:"mail" binding:"required"`
}

func UserSignUp(c *gin.Context) {
	var request userSignUp

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Encode user password
	passwordEncode, _ := encrypt.SaltedPasswordHash(request.Password)

	sqlStr := "INSERT INTO suglider.user_info(user_id, username, password, mail, address) VALUES (UNHEX(REPLACE(UUID(), '-', '')),?,?,?,?)"
	_, err = mariadb.DataBase.Exec(sqlStr, request.Username, passwordEncode, request.Mail, request.Address)
	if err != nil {
		log.Println("Insert user_info table failed:", err)
		c.JSON(http.StatusBadRequest, gin.H{"message": "User create failed"})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
	}
}

func UserDelete(c *gin.Context) {
	var request userDelete

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if request.User_id == "" {
		sqlStr := "DELETE FROM suglider.user_info WHERE username=? AND mail=?"
		_, err := mariadb.DataBase.Exec(sqlStr, request.Username, request.Mail)
		if err != nil {
			log.Println("Delete user_info data failed:", err)
			c.JSON(http.StatusBadRequest, gin.H{"message": "User delete failed"})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		}
	
	} else {
		// UNHEX(?) can convert user_id to binary(16)
		sqlStr := "DELETE FROM suglider.user_info WHERE user_id=UNHEX(?) AND username=? AND mail=?"
		_, err := mariadb.DataBase.Exec(sqlStr, request.User_id, request.Username, request.Mail)
		if err != nil {
			log.Println("Delete user_info data failed:", err)
			c.JSON(http.StatusBadRequest, gin.H{"message": "User delete failed"})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		}	
	}
}

