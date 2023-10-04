package handlers

import (
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	mariadb "suglider-auth/internal/database/connect"

)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Mail     string `json:"mail"`
	Address  string `json:"address"`
}

func UserSignUp(c *gin.Context) {
	var user User

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sqlStr := "INSERT INTO suglider.user_info(UNHEX(REPLACE(UUID(), '-', '')), username, password, mail, address) VALUES (?,?,?,?)"
	_, err = mariadb.DataBase.Exec(sqlStr, user.Username, user.Password, user.Mail, user.Address)
	if err != nil {
		log.Println("Insert user_info table failed:", err)
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
	}
}
