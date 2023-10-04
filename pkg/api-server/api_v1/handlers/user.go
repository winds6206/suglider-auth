package handlers

import (
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	mariadb "suglider-auth/internal/database/connect"

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

	sqlStr := "INSERT INTO suglider.user_info(UNHEX(REPLACE(UUID(), '-', '')), username, password, mail, address) VALUES (?,?,?,?)"
	_, err = mariadb.DataBase.Exec(sqlStr, request.Username, request.Password, request.Mail, request.Address)
	if err != nil {
		log.Println("Insert user_info table failed:", err)
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
		sqlStr := "DELETE FROM suglider.user_info WHERE username=?, mail=?"
		_, err := mariadb.DataBase.Exec(sqlStr, request.Username, request.Mail)
		if err != nil {
			log.Println("Delete user_info data failed:", err)
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		}
	
	} else {
		sqlStr := "DELETE FROM suglider.user_info WHERE user_id=?, username=?, mail=?"
		_, err := mariadb.DataBase.Exec(sqlStr, request.User_id, request.Username, request.Mail)
		if err != nil {
			log.Println("Delete user_info data failed:", err)
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		}	
	}
}

