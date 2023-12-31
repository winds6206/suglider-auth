package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	mariadb "suglider-auth/internal/database"
	"suglider-auth/internal/redis"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/encrypt"
	fmtv "suglider-auth/pkg/fmt_validator"
	"suglider-auth/pkg/jwt"
	"suglider-auth/pkg/session"
	"suglider-auth/pkg/totp"

	"github.com/gin-gonic/gin"
)

func ValidateMailOTP() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request otpData

		// Check the parameter transfer from POST
		err := c.ShouldBindJSON(&request)
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
			c.Abort()
			return
		}

		// Check whether user enable 2FA or not.
		userTwoFactorAuthData, err := mariadb.GetTwoFactorAuthByMail(request.Mail)

		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			c.Abort()
			return
		}

		if !userTwoFactorAuthData.MailOTPEnabled {
			c.JSON(http.StatusForbidden, utils.ErrorResponse(c, 1053, map[string]interface{}{
				"mail_otp_enabled": userTwoFactorAuthData.MailOTPEnabled,
			}))
			c.Abort()
			return
		}

		redisKey := encrypt.HashWithSHA(request.Mail, "sha1")

		value, errCode, err := redis.Get("mail_otp:" + redisKey)

		switch errCode {
		case 1043:
			errorMessage := fmt.Sprintf("Redis key does not exist: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			c.Abort()
			return

		case 1044:
			errorMessage := fmt.Sprintf("Redis GET data failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			c.Abort()
			return
		}

		// Verify OTP Code from user input
		if value == request.OTPCode {
			c.Set("mail_otp_verify", true)
			okSetSession := setSession(c, request.Mail)
			if !okSetSession {
				c.Abort()
				return
			}
			okSetJWT := setJWT(c, request.Mail)
			if !okSetJWT {
				c.Abort()
				return
			}
		} else {
			c.Set("mail_otp_verify", false)
		}

		c.Set("mail", request.Mail)
		c.Set("userName", userTwoFactorAuthData.UserName)
		c.Next()
	}
}

func ValidateTOTP() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request otpData

		// Check the parameter trasnfer from POST
		err := c.ShouldBindJSON(&request)
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
			c.Abort()
			return
		}

		// To get TOTP secret
		totpData, err := mariadb.TotpUserData(request.Mail)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
				c.Abort()
				return
			}
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
			c.Abort()
			return
		}

		if !totpData.TotpEnabled {
			c.JSON(http.StatusForbidden, utils.ErrorResponse(c, 1053, map[string]interface{}{
				"totp_enabled": totpData.TotpEnabled,
			}))
			c.Abort()
			return
		}

		// Verify TOTP Code from user input
		valid := totp.TotpValidate(request.OTPCode, totpData.TotpSecret)

		if valid {
			c.Set("totp_verify", true)
			okSetSession := setSession(c, request.Mail)
			if !okSetSession {
				c.Abort()
				return
			}
			okSetJWT := setJWT(c, request.Mail)
			if !okSetJWT {
				c.Abort()
				return
			}

		} else {
			c.Set("totp_verify", false)
		}

		c.Set("mail", request.Mail)
		c.Set("userName", totpData.UserName)
		c.Next()
	}
}

func LoginStatusCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request userLogin
		var account string
		var data rdsValeData

		// Check the parameter trasnfer from POST
		err := c.ShouldBindJSON(&request)
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
			c.Abort()
			return
		}

		account = request.Account

		// Check whether user input data is mail format or not.
		mailValid := fmtv.MailValidator(account)

		if !mailValid {

			userInfo, err := mariadb.GetUserInfoByUserName(account)
			if err != nil {
				if err == sql.ErrNoRows {
					c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1048, err))
					c.Abort()
					return
				}
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
				c.Abort()
				return
			}
			account = userInfo.Mail
		}

		// Check whether login status exists in redis or not.
		value, errCode, err := redis.Get("login_status:" + account)

		switch errCode {
		// Key not exists
		case 1043:

			c.Set("mail", account)
			c.Set("password", request.Password)
			c.Next()

		case 1044:
			errorMessage := fmt.Sprintf("Redis GET data failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			c.Abort()
			return
		// Key exists
		case 0:
			err := json.Unmarshal([]byte(value), &data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1063, err))
				c.Abort()
				return
			}
			c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
				"mail":             data.Mail,
				"username":         data.UserName,
				"account_passed":   data.AccountPassed,
				"mail_otp_passed":  data.MailOTPPassed,
				"sms_otp_passed":   data.SmsOTPPassed,
				"totp_passed":      data.TotpPassed,
				"totp_enabled":     data.TotpEnabled,
				"mail_otp_enabled": data.MailOTPEnabled,
				"sms_otp_enabled":  data.SmsOTPEnabled,
			}))
			c.Abort()
			return
		}
	}
}

func setSession(c *gin.Context, mail string) bool {

	// Check session exist or not
	ok, err := session.CheckSession(c)
	if err != nil {
		errorMessage := fmt.Sprintf("Checking whether key exist or not happen something wrong: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1039, err))
		return false
	}
	if !ok {
		_, errCode, err := session.AddSession(c, mail)
		switch errCode {
		case 1041:
			errorMessage := fmt.Sprintf("Failed to create session value JSON data: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return false

		case 1042:
			errorMessage := fmt.Sprintf("Redis SET data failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return false
		}
	} else {
		sid, _, errCode, err := session.ReadSession(c)

		switch errCode {
		case 1043:
			errorMessage := fmt.Sprintf("Redis key does not exist: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return false

		case 1044:
			errorMessage := fmt.Sprintf("Redis GET data failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return false

		case 1063:
			errorMessage := fmt.Sprintf("The json data unmarshal failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return false
		}

		err = session.DeleteSession(sid)
		if err != nil {
			errorMessage := fmt.Sprintf("Delete key(sid:%s) failed: %v", sid, err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1040, err))
			return false
		}
		_, errCode, err = session.AddSession(c, mail)
		switch errCode {
		case 1041:
			errorMessage := fmt.Sprintf("Failed to create session value JSON data: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return false

		case 1042:
			errorMessage := fmt.Sprintf("Redis SET data failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return false
		}
	}

	return true
}

func setJWT(c *gin.Context, mail string) bool {

	token, expireTimeSec, err := jwt.GenerateJWT(mail)

	if err != nil {
		errorMessage := fmt.Sprintf("Generate the JWT string failed: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1014, err))
		return false
	}

	c.SetCookie("token", token, expireTimeSec, "/", "localhost", false, true)
	return true
}
