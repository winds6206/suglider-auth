package handlers

import (
	"log"
	"net/http"
	"github.com/gin-gonic/gin"
	mariadb "suglider-auth/internal/database"
	"suglider-auth/pkg/encrypt"
	"database/sql"
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
	var err error

	// Check the parameter trasnfer from POST
	err = c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Encode user password
	passwordEncode, _ := encrypt.SaltedPasswordHash(request.Password)

	err = mariadb.UserSignUp(request.Username, passwordEncode, request.Mail, request.Address)
	if err != nil {
		log.Println("Insert user_info table failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
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
		result, err := mariadb.UserDelete(request.Username, request.Mail)

		// First, check if error or not
		if err != nil {
			log.Println("Delete user_info data failed:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		} 

		// Second, get affected row
		rowsAffected, _ := result.RowsAffected()

		if rowsAffected == 0 {
			c.JSON(http.StatusOK, gin.H{"message": "No search this user"})
		} else if rowsAffected > 0 {
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		}
	} else {

		result, err := mariadb.UserDeleteByUUID(request.User_id, request.Username, request.Mail)

		// First, check if error or not
		if err != nil {
			log.Println("Delete user_info data failed:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		} 

		// Second, get affected row
		rowsAffected, _ := result.RowsAffected()

		if rowsAffected == 0 {
			c.JSON(http.StatusOK, gin.H{"message": "No search this user"})
		} else if rowsAffected > 0 {
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
	// var userDBInfo userDBInfo

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check whether username exist or not
	userInfo, err := mariadb.UserLogin(request.Username)

	// No err means user exist
	if err == nil {

		pwdVerify := encrypt.VerifySaltedPasswordHash(userInfo.Password, request.Password)

		// Check password true or false
		if pwdVerify {		
			c.JSON(http.StatusOK, gin.H{"message": "User Logined successfully"})
		} else if !pwdVerify {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

	} else if err == sql.ErrNoRows {
		log.Println("User Login failed:", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		log.Println("Login failed:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	sid := session.ReadSession(c)

	// Check session exist or not
	ok := session.CheckSession(c)
	if !ok {
		session.AddSession(c, request.Username)
	} else {
		session.DeleteSession(sid)
		session.AddSession(c, request.Username)
	}

}

func UserLogOut(c *gin.Context) {

	sid := session.ReadSession(c)

	// Check session exist or not
	ok := session.CheckSession(c)
	if !ok {
		log.Printf("session ID %s doesn't exsit in redis\n", sid)
		return
	}

	session.DeleteSession(sid)
}

// Test Function
func Test(c *gin.Context) {
	// session.AddSession(c, "tony")
	sid := session.ReadSession(c)
	log.Printf("sid:%s\n", sid)
	
	if sid == "<nil>" {
		log.Println("sid is nil")
	}

}

// Test Function
func Testv2(c *gin.Context) {

	sid := session.ReadSession(c)
	log.Println("sid:", sid)

	// Check session exist or not	
	ok := session.CheckSession(c)
	if !ok {
		log.Printf("session ID %s doesn't exsit in redis\n", sid)
		return
	}

	session.DeleteSession(sid)

}