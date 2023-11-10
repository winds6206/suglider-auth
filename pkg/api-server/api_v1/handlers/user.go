package handlers

import (
	"log/slog"
	"net/http"
	"fmt"
	"github.com/gin-gonic/gin"
	mariadb "suglider-auth/internal/database"
	"suglider-auth/pkg/encrypt"
	"database/sql"
	"suglider-auth/pkg/session"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/jwt"
	// "time"
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
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Encode user password
	passwordEncode, _ := encrypt.SaltedPasswordHash(request.Password)

	err = mariadb.UserSignUp(request.Username, passwordEncode, request.Mail, request.Address)
	if err != nil {
		errorMessage := fmt.Sprintf("Insert user_info table failed: %v", err)
		slog.Error(errorMessage)

		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
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
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	if request.User_id == "" {
		result, err := mariadb.UserDelete(request.Username, request.Mail)

		// First, check if error or not
		if err != nil {
			errorMessage := fmt.Sprintf("Delete user_info data failed: %v", err)
			slog.Error(errorMessage)

			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		} 

		// Second, get affected row
		rowsAffected, _ := result.RowsAffected()

		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, utils.ErrorResponse(c, 1003))
		} else if rowsAffected > 0 {
			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
		}
	} else {

		result, err := mariadb.UserDeleteByUUID(request.User_id, request.Username, request.Mail)

		// First, check if error or not
		if err != nil {
			errorMessage := fmt.Sprintf("Delete user_info data failed: %v", err)
			slog.Error(errorMessage)

			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		} 

		// Second, get affected row
		rowsAffected, _ := result.RowsAffected()

		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, utils.ErrorResponse(c, 1003))
		} else if rowsAffected > 0 {
			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
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

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Check whether username exist or not
	userInfo, err := mariadb.UserLogin(request.Username)

	// No err means user exist
	if err == nil {

		pwdVerify := encrypt.VerifySaltedPasswordHash(userInfo.Password, request.Password)

		// Check password true or false
		if pwdVerify {
			
			// Check whether user enable TOTP or not.
			totpUserData, errTotpUserData := mariadb.TotpUserData(userInfo.Username)

			// Check error type
			if errTotpUserData != nil {

				// ErrNoRows means user never enable TOTP feature
				if errTotpUserData == sql.ErrNoRows {
					
					fmt.Println("ErrNoRows session start")
					sid := session.ReadSession(c)

					// Check session exist or not
					ok := session.CheckSession(c)
					if !ok {
						_, err := session.AddSession(c, request.Username)
						if err != nil {
							c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1005, err))
							return
						}
					} else {
						session.DeleteSession(sid)
						_, err := session.AddSession(c, request.Username)
						if err != nil {
							c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1005, err))
							return
						}
					}

					fmt.Println("ErrNoRows session finish")

					c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
						"username": request.Username,
						"totp_enabled": totpUserData.TotpEnabled,
					}))

				} else {
					c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
					return
				}
			
			// No error means user had ever enabled TOTP and data is in the database
			} else if totpUserData.TotpEnabled == true {
				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"username": request.Username,
					"totp_enabled": totpUserData.TotpEnabled,
				}))
			} else {

				fmt.Println("TotpEnabled = false, session start")

				sid := session.ReadSession(c)

				// Check session exist or not
				ok := session.CheckSession(c)
				if !ok {
					_, err := session.AddSession(c, request.Username)
					if err != nil {
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1005, err))
						return
					}
				} else {
					session.DeleteSession(sid)
					_, err := session.AddSession(c, request.Username)
					if err != nil {
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1005, err))
						return
					}
				}

				fmt.Println("TotpEnabled = false, session finish")

				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"username": request.Username,
					"totp_enabled": totpUserData.TotpEnabled,
				}))
			}
		} else {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1004))
			return
		}

	} else if err == sql.ErrNoRows {
		errorMessage := fmt.Sprintf("User Login failed: %v", err)
		slog.Error(errorMessage)

		c.JSON(http.StatusNotFound, utils.ErrorResponse(c, 1003, err))
		return
	} else if err != nil {
		errorMessage := fmt.Sprintf("Login failed: %v", err)
		slog.Error(errorMessage)

		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}
}

func UserLogout(c *gin.Context) {

	sid := session.ReadSession(c)

	// Check session exist or not
	ok := session.CheckSession(c)
	if !ok {
		slog.Info(fmt.Sprintf("session ID %s doesn't exsit in redis", sid))
		return
	}

	session.DeleteSession(sid)
}

// Test Function
func TestLogout(c *gin.Context) {
	// immediately clear the token cookie
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
}

// Test Function
func TestLogin(c *gin.Context) {

	var request userLogin

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	token, expirationTime, err := jwt.GenerateJWT(request.Username)

	if err != nil {
		// TODO
		return
	}

	fmt.Println(token)
	fmt.Println(expirationTime)

	// sec, _ := time.ParseDuration(expirationTime)
	// fmt.Println(sec)

	// c.SetCookie("token", token, sec, "/", "localhost", false, true)

}

func TestWelcome(c *gin.Context) {

	cookie, err := c.Cookie("token")
	if err != nil {
		// If the cookie is not set, return an unauthorized status
		// TODO
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1003, err))
		return
	}

	parseData, _ := jwt.ParseJWT(cookie)

	c.JSON(http.StatusOK, gin.H{
		"username": parseData,
	})


}

func TestRefresh(c *gin.Context) {

	cookie, err := c.Cookie("token")
	if err != nil {
		// If the cookie is not set, return an unauthorized status
		// TODO
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1003, err))
		return
	}

	_, errParseJWT := jwt.ParseJWT(cookie)

	if errParseJWT != nil {
		// TODO
	}

	token, expirationTime, err := jwt.RefreshJWT(cookie)

	if err != nil {
		// TODO
	}

	fmt.Println(token)
	fmt.Println(expirationTime)

	// Set the new token as the users `token` cookie
	c.SetCookie("token", token, expirationTime, "/", "localhost", false, true)


}
