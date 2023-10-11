package handlers

import (
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	mariadb "suglider-auth/internal/database/connect"
	"suglider-auth/pkg/encrypt"
	"database/sql"
	// "fmt"
	// "time"
	"suglider-auth/pkg/session"
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

type userLogin struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type userDBInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// @Summary Sign Up User
// @Description registry new user
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param password formData string false "Password"
// @Param mail formData string false "e-Mail"
// @Param address formData string false "Address"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/sign-up [post]
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

// @Summary Delete User
// @Description delete an existing user
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param mail formData string false "e-Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/delete [post]
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
			return
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
			return
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		}	
	}
}

// @Summary User Login
// @Description user login
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param password formData string false "Password"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/login [post]
func UserLogin(c *gin.Context) {

	var request userLogin
	var userDBInfo userDBInfo
	var usernameExist int

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check whether username exist or not
	err = mariadb.DataBase.Get(&userDBInfo, "SELECT username, password FROM suglider.user_info WHERE username=?", request.Username)

	if err == nil {
		usernameExist = 1
	} else if err == sql.ErrNoRows {
		log.Println("User Login failed:", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	pwdVerify := encrypt.VerifySaltedPasswordHash(userDBInfo.Password, request.Password)

	// Check password true or false
	if usernameExist == 1 && pwdVerify {
		c.JSON(http.StatusOK, gin.H{"message": "User Logined successfully"})
	} else if !pwdVerify {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	session.AddSession(c)

}

// Test Function
func Test(c *gin.Context) {

	session.AddSession(c)

}

// Test Function
func Testv2(c *gin.Context) {

	session.ReadSession(c)
}