package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	mariadb "suglider-auth/internal/database"
	smtp "suglider-auth/internal/mail"
	"suglider-auth/internal/redis"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/encrypt"
	fmtv "suglider-auth/pkg/fmt_validator"
	"suglider-auth/pkg/jwt"
	"suglider-auth/pkg/session"
	"suglider-auth/pkg/time_convert"
	"time"

	"github.com/gin-gonic/gin"
)

// @Summary Sign Up User
// @Description registry new user
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param password formData string false "Password"
// @Param username formData string false "User Name"
// @Param first_name formData string false "First Name"
// @Param last_name formData string false "Last Name"
// @Param phone_number formData string false "Phone Number"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/sign-up [post]
func UserSignUp(c *gin.Context) {
	var request userSignUp
	var err error
	var user string

	// Check the parameter trasnfer from POST
	err = c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	err = fmtv.FmtValidator(request.Mail, request.Password)
	if err != nil {

		errorMessage := fmt.Sprintf("%v", err)
		slog.Error(errorMessage)

		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1021, err))
		return
	}

	// Remove temporary
	// if request.PhoneNumber != nil && *request.PhoneNumber != "" {
	// 	ok := fmtv.PhoneNumberValidator(request.PhoneNumber)
	// 	if !ok {
	// 		slog.Error("Phone Number is not satisfied of rule.")
	// 		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1021, nil))
	// 		return
	// 	}
	// }

	if request.FirstName == nil {
		request.FirstName = nil
	}
	if request.LastName == nil {
		request.LastName = nil
	}
	if request.UserName == nil || *request.UserName == "" {
		request.UserName = nil
	}
	if request.PhoneNumber == nil || *request.PhoneNumber == "" {
		request.PhoneNumber = nil
	}

	userInfo, err := mariadb.GetPasswordByMail(request.Mail)

	// No err means user exist
	// sql.ErrNoRows indicates that there were no results found for the username provided.
	if err == sql.ErrNoRows {

		// Encode user password
		passwordEncode, _ := encrypt.SaltedPasswordHash(request.Password)

		err = mariadb.UserSignUp(request.Mail, passwordEncode, request.UserName, request.FirstName, request.LastName, request.PhoneNumber)
		if err != nil {
			errorMessage := fmt.Sprintf("Insert user_info table failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		// Look up user ID
		userInfo, err := mariadb.LookupUserID(request.Mail)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
				return
			}
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		// Insert personal_info table by user_id
		err = mariadb.InsertPersonalInfo(userInfo.UserID)
		if err != nil {
			errorMessage := fmt.Sprintf("Insert personal_info table failed: %v", err)
			slog.Error(errorMessage)

			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			return
		}

		// The condition means the user had previously signed up through OAuth2.
	} else if err == nil && !userInfo.Password.Valid {

		// Encode user password
		passwordEncode, _ := encrypt.SaltedPasswordHash(request.Password)

		err = mariadb.UpdateSignUp(request.Mail, passwordEncode, request.UserName, request.FirstName, request.LastName, request.PhoneNumber)
		if err != nil {
			errorMessage := fmt.Sprintf("Update user_info table failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1037, err))
			return
		}
		// Account have already existed
	} else if err == nil && userInfo.Password.Valid {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(c, 1056, err))
		return
		// Other error condition
	} else if err != nil {
		errorMessage := fmt.Sprintf("Sign up failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	// Mail user name decision logic
	if request.FirstName != nil && *request.FirstName != "" {
		user = *request.FirstName
	} else if request.UserName != nil && *request.UserName != "" {
		user = *request.UserName
	} else {
		re := regexp.MustCompile(`([^@]+)@`)
		match := re.FindStringSubmatch(request.Mail)
		if len(match) > 1 {
			user = match[1]
		} else {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1054, err))
			return
		}
	}

	// mail verification
	if err = smtp.SendVerifyMail(c, user, request.Mail); err != nil {
		slog.Error(err.Error())
	}
	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))

}

// @Summary Delete Account
// @Description delete an existing account.
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/delete [delete]
func UserDelete(c *gin.Context) {
	var request mailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	result, err := mariadb.UserDeleteByMail(request.Mail)
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

// @Summary User Login
// @Description user login
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param account formData string false "Enter mail or username"
// @Param password formData string false "Password"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/login [post]
func UserLogin(c *gin.Context) {

	mailValue, isMailExists := c.Get("mail")
	passwordValue, isPasswordExists := c.Get("password")

	if !isMailExists || !isPasswordExists {
		slog.Error("It's either that the mail doesn't exist or password.")
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1067, nil))
		return
	}

	// Convert interface to string
	mail := fmt.Sprintf("%v", mailValue)
	password := fmt.Sprintf("%v", passwordValue)

	userInfo, err := mariadb.GetPasswordByMail(mail)

	// No err means user exist
	if err == nil && userInfo.Password.Valid {

		// Check password true or false
		pwdVerify := encrypt.VerifySaltedPasswordHash(userInfo.Password.String, password)

		// Password passed
		if pwdVerify {

			// Check whether user enable 2FA or not.
			userTwoFactorAuthData, err := mariadb.GetTwoFactorAuthByMail(userInfo.Mail)

			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
				return
			}

			// These conditions indicate that user have enabled the 2FA feature.
			if userTwoFactorAuthData.TotpEnabled.Bool ||
				userTwoFactorAuthData.SmsOTPEnabled ||
				userTwoFactorAuthData.MailOTPEnabled {

				// Store value into struct
				userNameData := &UserName{
					String: userInfo.Username.String,
					Valid:  userInfo.Username.Valid,
				}

				rdsValue := &rdsValeData{
					Mail:           userInfo.Mail,
					UserName:       *userNameData,
					AccountPassed:  true,
					TotpEnabled:    userTwoFactorAuthData.TotpEnabled.Bool,
					MailOTPEnabled: userTwoFactorAuthData.MailOTPEnabled,
					SmsOTPEnabled:  userTwoFactorAuthData.SmsOTPEnabled,
				}

				jsonData, err := json.Marshal(rdsValue)
				if err != nil {
					c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1063, err))
					return
				}

				redisTTL, _, err := time_convert.ConvertTimeFormat("15m")
				if err != nil {
					c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1069, err))
					return
				}

				// Set login_status into redis
				err = redis.Set("login_status:"+userInfo.Mail, string(jsonData), redisTTL)

				if err != nil {
					errorMessage := fmt.Sprintf("Redis SET data failed.: %v", err)
					slog.Error(errorMessage)
					c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1042, err))
					return
				}

				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"mail":             userInfo.Mail,
					"username":         userInfo.Username,
					"totp_enabled":     userTwoFactorAuthData.TotpEnabled.Bool,
					"mail_otp_enabled": userTwoFactorAuthData.MailOTPEnabled,
					"sms_otp_enabled":  userTwoFactorAuthData.SmsOTPEnabled,
				}))

				// The user has not enabled the 2FA feature.
			} else {
				okSetSession := setSession(c, userInfo.Mail)
				if !okSetSession {
					return
				}
				okSetJWT := setJWT(c, userInfo.Mail)
				if !okSetJWT {
					return
				}

				c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
					"mail":     userInfo.Mail,
					"username": userInfo.Username,
				}))
			}
			// Password is not correct.
		} else {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1004))
			return
		}
	} else if err == nil && !userInfo.Password.Valid {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1004, map[string]interface{}{
			"mail": mail,
			"msg":  "Login failed: password is NULL, indicating the user had previously signed up through OAuth2.",
		}))
		return
		// sql.ErrNoRows indicates that there were no results found for the username provided.
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
	sid, _, errCode, err := session.ReadSession(c)

	switch errCode {
	case 1043:
		errorMessage := fmt.Sprintf("Redis key does not exist: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
		return

	case 1044:
		errorMessage := fmt.Sprintf("Redis GET data failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
		return

	case 1063:
		errorMessage := fmt.Sprintf("The json data unmarshal failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
		return
	}

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
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1019, map[string]interface{}{
				"msg": "JWT can't found.",
			}))
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

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary User Password Expire Check
// @Description Check whether a user's password has expired or not
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/password-expire [get]
func PasswordExpire(c *gin.Context) {

	var request mailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	resultData, err := mariadb.GetPasswordExpireByMail(request.Mail)

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
			"mail":                 resultData.Mail,
			"password_expire_date": resultData.PasswordExpireDate,
			"expired":              true,
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":                 resultData.Mail,
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
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/password-extension [patch]
func PasswordExtension(c *gin.Context) {
	var request mailOperate
	var err error

	// Check the parameter trasnfer from POST
	err = c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	err = mariadb.PasswordExtensionByMail(request.Mail)

	if err != nil {
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
func CheckUserName(c *gin.Context) {
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

	var request mailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	count, err := mariadb.CheckMailExists(request.Mail)

	if err != nil {
		errorMessage := fmt.Sprintf("Check whether the mail exists or not failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1046, err))
	}

	if count == 1 {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":  request.Mail,
			"exist": true,
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":  request.Mail,
			"exist": false,
		}))
	}

}

// @Summary Change Password
// @Description Users change password by themselves
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param old_password formData string false "Old Password"
// @Param new_password formData string false "New Password"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/change-password [patch]
func ChangePassword(c *gin.Context) {
	var request resetPassword

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userInfo, err := mariadb.GetPasswordByMail(request.Mail)
	// No err means user exist
	if err == nil && userInfo.Password.Valid {

		pwdVerify := encrypt.VerifySaltedPasswordHash(userInfo.Password.String, request.OldPassword)

		// Check old password true or false
		if pwdVerify {

			// Check new password column rule
			valid := fmtv.PasswordValidator(request.NewPassword)
			if valid {

				// Check whether new password is the same as old one or not
				notPass := encrypt.VerifySaltedPasswordHash(userInfo.Password.String, request.NewPassword)
				if !notPass {

					// Encode user new password
					newPasswordEncode, _ := encrypt.SaltedPasswordHash(request.NewPassword)

					// Change user password
					err := mariadb.UserResetPassword(c, userInfo.Mail, newPasswordEncode)
					if err != nil {
						c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1027, err))
						return
					}
					c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
						"mail": userInfo.Mail,
						"msg":  "Change password successfully.",
					}))

				} else {
					c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1059, err))
					return

				}
			} else {
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1058, nil))
				return
			}
		} else {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1004))
			return
		}
	} else if err == nil && !userInfo.Password.Valid {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(c, 1004, map[string]interface{}{
			"mail": request.Mail,
			"msg":  "Reset failed: password is invalid, indicating the user had previously signed up through OAuth2. Please sign up using genernal or use OAuth2 to login and setup password.",
		}))
		return

		// sql.ErrNoRows indicates that there were no results found for the username provided.
	} else if err == sql.ErrNoRows {
		errorMessage := fmt.Sprintf("No search this mail: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusNotFound, utils.ErrorResponse(c, 1057, err))
		return

	} else if err != nil {
		errorMessage := fmt.Sprintf("Reset password failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

}

// @Summary Set Up Password
// @Description When user sign up through OAuth2, use this API to set up their password
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param password formData string false "Password"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/setup-password [patch]
func SetUpPassword(c *gin.Context) {
	var request setUpPassword

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userInfo, err := mariadb.GetPasswordByMail(request.Mail)
	// No err means user exist
	if err == nil && userInfo.Password.Valid {

		c.JSON(http.StatusForbidden, utils.ErrorResponse(c, 1060, nil))
		return

	} else if err == nil && !userInfo.Password.Valid {

		// Check password column rule
		valid := fmtv.PasswordValidator(request.Password)
		if valid {
			// Encode user password
			passwordEncode, _ := encrypt.SaltedPasswordHash(request.Password)

			// Change user password
			err := mariadb.UserResetPassword(c, userInfo.Mail, passwordEncode)
			if err != nil {
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1027, err))
				return
			}
			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
				"mail": userInfo.Mail,
				"msg":  "Set up password successfully.",
			}))
		} else {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1058, nil))
			return
		}

		// sql.ErrNoRows indicates that there were no results found for the username provided.
	} else if err == sql.ErrNoRows {
		errorMessage := fmt.Sprintf("No search this mail: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusNotFound, utils.ErrorResponse(c, 1057, err))
		return

	} else if err != nil {
		errorMessage := fmt.Sprintf("Reset password failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

}

// @Summary Update Personal Information
// @Description Update Personal Information.
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param username formData string false "User Name"
// @Param last_name formData string false "Last Name"
// @Param first_name formData string false "First Name"
// @Param phone_number formData string false "Phone Number"
// @Param address formData string false "Address"
// @Param birthday formData string false "Birthday"
// @Param sex formData string false "Sex"
// @Param blood_type formData string false "Blood Type"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/update-personal-info [put]
func UpdatePersonalInfo(c *gin.Context) {

	var request updatePersonalInfo

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	if request.PhoneNumber != nil && *request.PhoneNumber != "" {
		ok := fmtv.PhoneNumberValidator(request.PhoneNumber)
		if !ok {
			slog.Error("Phone Number is not satisfied of format rule.")
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1021, nil))
			return
		}
	}

	if request.Birthday != nil && *request.Birthday != "" {
		ok := fmtv.DateValidator(request.Birthday)
		if !ok {
			slog.Error("Birthday is not satisfied of format rule.")
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1021, nil))
			return
		}
	}

	if request.FirstName == nil {
		request.FirstName = nil
	}
	if request.LastName == nil {
		request.LastName = nil
	}
	if request.Address == nil {
		request.Address = nil
	}
	if request.Birthday == nil || *request.Birthday == "" {
		request.Birthday = nil
	}
	if request.Sex == nil {
		request.Sex = nil
	}
	if request.BloodType == nil {
		request.BloodType = nil
	}
	if request.UserName == nil || *request.UserName == "" {
		request.UserName = nil
	}
	if request.PhoneNumber == nil || *request.PhoneNumber == "" {
		request.PhoneNumber = nil
	}

	err = mariadb.UpdatePersonalInfoByMail(request.Mail, request.UserName, request.LastName, request.FirstName, request.PhoneNumber, request.Address, request.Birthday, request.Sex, request.BloodType)
	if err != nil {
		errorMessage := fmt.Sprintf("Update personal information failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1066, err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
		"mail": request.Mail,
		"msg":  "Update personal information successfully.",
	}))

}

// @Summary Phone Number Check
// @Description Check whether the phone number exists or not
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param phone_number formData string false "Phone Number"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/check-phone-number [get]
func CheckPhoneNumber(c *gin.Context) {

	var request phoneNumberOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	count, err := mariadb.CheckPhoneNumberExists(request.PhoneNumber)

	if err != nil {
		errorMessage := fmt.Sprintf("Check whether the phone number exists or not failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1070, err))
	}

	if count == 1 {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":  request.PhoneNumber,
			"exist": true,
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":  request.PhoneNumber,
			"exist": false,
		}))
	}

}
