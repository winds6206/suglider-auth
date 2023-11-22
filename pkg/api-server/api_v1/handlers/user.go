package handlers

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	mariadb "suglider-auth/internal/database"
	smtp "suglider-auth/internal/mail"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/encrypt"
	"suglider-auth/pkg/jwt"
	pwd_validator "suglider-auth/pkg/pwd-validator"
	"suglider-auth/pkg/session"
	"time"

	"github.com/gin-gonic/gin"
)

type userSignUp struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	ComfirmPwd string `json:"comfirm_pwd" binding:"required"`
	Mail       string `json:"mail" binding:"required"`
	Address    string `json:"address" binding:"required"`
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

type userNameOperate struct {
	UserName string `json:"username" binding:"required"`
}

type MailOperate struct {
	Mail string `json:"mail" binding:"required"`
}

// @Summary Sign Up User
// @Description registry new user
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param password formData string false "Password"
// @Param comfirm_pwd formData string false "Comfirm Password"
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

	errPwdValidator := pwd_validator.PwdValidator(request.Username, request.Password, request.Mail)
	if errPwdValidator != nil {

		errorMessage := fmt.Sprintf("%v", errPwdValidator)
		slog.Error(errorMessage)

		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1021, errPwdValidator))
		return
	}

	// Encode user password
	passwordEncode, _ := encrypt.SaltedPasswordHash(request.Password)
	comfirmPwdEncode, _ := encrypt.SaltedPasswordHash(request.ComfirmPwd)

	fmt.Println(passwordEncode)

	err = mariadb.UserSignUp(request.Username, passwordEncode, comfirmPwdEncode, request.Mail, request.Address)
	if err != nil {
		errorMessage := fmt.Sprintf("Insert user_info table failed: %v", err)
		slog.Error(errorMessage)

		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	} else {
		// mail verification
		if err = smtp.SendVerifyMail(c, request.Username, request.Mail); err != nil {
			slog.Error(err.Error())
		}
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
// @Router /api/v1/user/delete [delete]
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

					sid := session.ReadSession(c)

					// Check session exist or not
					ok, err := session.CheckSession(c)
					if err != nil {
						errorMessage := fmt.Sprintf("Checking whether key exist or not happen something wrong: %v", err)
						slog.Error(errorMessage)

						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1039, err))
						return
					}
					if !ok {
						_, errCode, err := session.AddSession(c, request.Username)
						switch errCode {
						case 1041:
							errorMessage := fmt.Sprintf("Failed to create session value JSON data: %v", err)
							slog.Error(errorMessage)
							c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
							return

						case 1042:
							errorMessage := fmt.Sprintf("Redis SET data failed: %v", err)
							slog.Error(errorMessage)
							c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
							return
						}
					} else {
						err = session.DeleteSession(sid)
						if err != nil {
							errorMessage := fmt.Sprintf("Delete key(sid:%s) failed: %v", sid, err)
							slog.Error(errorMessage)

							c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1040, err))
							return
						}
						_, errCode, err := session.AddSession(c, request.Username)
						switch errCode {
						case 1041:
							errorMessage := fmt.Sprintf("Failed to create session value JSON data: %v", err)
							slog.Error(errorMessage)
							c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
							return

						case 1042:
							errorMessage := fmt.Sprintf("Redis SET data failed: %v", err)
							slog.Error(errorMessage)
							c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
							return
						}
					}

					token, expireTimeSec, err := jwt.GenerateJWT(request.Username)

					if err != nil {
						errorMessage := fmt.Sprintf("Generate the JWT string failed: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1014, err))

						return
					}

					c.SetCookie("token", token, expireTimeSec, "/", "localhost", false, true)

					c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
						"username":     request.Username,
						"totp_enabled": totpUserData.TotpEnabled,
					}))

				} else {
					c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
					return
				}

				// No error means user had ever enabled TOTP and data is in the database.
				// This block means totpUserData.TotpEnabled = true
			} else if totpUserData.TotpEnabled {
				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"username":     request.Username,
					"totp_enabled": totpUserData.TotpEnabled,
				}))

				// This block means totpUserData.TotpEnabled = false
			} else {

				sid := session.ReadSession(c)

				// Check session exist or not
				ok, err := session.CheckSession(c)
				if err != nil {
					errorMessage := fmt.Sprintf("Checking whether key exist or not happen something wrong: %v", err)
					slog.Error(errorMessage)

					c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1039, err))
					return
				}
				if !ok {
					_, errCode, err := session.AddSession(c, request.Username)
					switch errCode {
					case 1041:
						errorMessage := fmt.Sprintf("Failed to create session value JSON data: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
						return

					case 1042:
						errorMessage := fmt.Sprintf("Redis SET data failed: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
						return
					}
				} else {
					err = session.DeleteSession(sid)
					if err != nil {
						errorMessage := fmt.Sprintf("Delete key(sid:%s) failed: %v", sid, err)
						slog.Error(errorMessage)

						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1040, err))
						return
					}
					_, errCode, err := session.AddSession(c, request.Username)
					switch errCode {
					case 1041:
						errorMessage := fmt.Sprintf("Failed to create session value JSON data: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
						return

					case 1042:
						errorMessage := fmt.Sprintf("Redis SET data failed: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
						return
					}
				}

				token, expireTimeSec, err := jwt.GenerateJWT(request.Username)

				if err != nil {
					errorMessage := fmt.Sprintf("Generate the JWT string failed: %v", err)
					slog.Error(errorMessage)
					c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1014, err))

					return
				}

				c.SetCookie("token", token, expireTimeSec, "/", "localhost", false, true)

				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"username":     request.Username,
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

// @Summary User Logout
// @Description user logout
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/logout [post]
func UserLogout(c *gin.Context) {

	// Clear JWT
	c.SetCookie("token", "", -1, "/", "localhost", false, true)

	// Clear session
	sid := session.ReadSession(c)

	// Check session exist or not
	ok, err := session.CheckSession(c)
	if err != nil {
		errorMessage := fmt.Sprintf("Checking whether key exist or not happen something wrong: %v", err)
		slog.Error(errorMessage)

		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1039, err))
		return
	}
	if !ok {
		slog.Info(fmt.Sprintf("session ID %s doesn't exsit in redis", sid))
		return
	}

	err = session.DeleteSession(sid)
	if err != nil {
		errorMessage := fmt.Sprintf("Delete key(sid:%s) failed: %v", sid, err)
		slog.Error(errorMessage)

		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1040, err))
		return
	}
}

// @Summary User Refresh JWT
// @Description user refresh JWT
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/refresh [get]
func RefreshJWT(c *gin.Context) {

	cookie, err := c.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1019, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1020, err))
		return
	}

	_, errCode, errParseJWT := jwt.ParseJWT(cookie)

	if errParseJWT != nil {

		switch errCode {

		case 1015:
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, errCode, err))
			return

		case 1016:
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, errCode, err))
			return

		case 1017:
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, errCode, err))
			return
		}
	}

	token, expireTimeSec, err := jwt.RefreshJWT(cookie)

	if err != nil {
		errorMessage := fmt.Sprintf("Generate new JWT failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1018, err))

		return
	}

	// Set the new token as the users `token` cookie
	c.SetCookie("token", token, expireTimeSec, "/", "localhost", false, true)
}

// @Summary User Password Expire Check
// @Description Check whether a user's password has expired or not
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/password-expire [get]
func PasswordExpire(c *gin.Context) {

	var request userNameOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	resultData, err := mariadb.PasswordExpire(request.UserName)

	if err != nil {
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1003, err))
				return
			}
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}
	}

	// Convert string to data
	parsedDate, err := time.Parse("2006-01-02", resultData.PasswordExpireDate)
	if err != nil {
		errorMessage := fmt.Sprintf("Parse date failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1036, err))

		return
	}

	todayDate := time.Now().UTC().Truncate(24 * time.Hour)

	if todayDate.After(parsedDate) {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username":             resultData.Username,
			"password_expire_date": resultData.PasswordExpireDate,
			"expired":              true,
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username":             resultData.Username,
			"password_expire_date": resultData.PasswordExpireDate,
			"expired":              false,
		}))
	}
}

// @Summary User Password Extension
// @Description Extension user's password
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/password-extension [patch]
func PasswordExtension(c *gin.Context) {
	var request userNameOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	errPasswordExtension := mariadb.PasswordExtension(request.UserName)

	if errPasswordExtension != nil {
		errorMessage := fmt.Sprintf("Update user_info table failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1037, err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary Username Check
// @Description Check whether the username exists or not
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/check-username [get]
func CheckUsername(c *gin.Context) {
	var request userNameOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	count, err := mariadb.CheckUsername(request.UserName)

	if err != nil {
		errorMessage := fmt.Sprintf("Check whether the username exists or not failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1045, err))
	}

	if count == 1 {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username": request.UserName,
			"exist":    true,
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username": request.UserName,
			"exist":    false,
		}))
	}

}

// @Summary Mail Check
// @Description Check whether the mail exists or not
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/check-mail [get]
func CheckMail(c *gin.Context) {

	var request MailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	count, err := mariadb.CheckMail(request.Mail)

	if err != nil {
		errorMessage := fmt.Sprintf("Check whether the mail exists or not failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1046, err))
	}

	if count == 1 {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username": request.Mail,
			"exist":    true,
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username": request.Mail,
			"exist":    false,
		}))
	}

}
