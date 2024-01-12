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
	"suglider-auth/pkg/time_convert"

	"github.com/gin-gonic/gin"
)

// @Summary Mail OTP Enable
// @Description Enable Mail OTP feature
// @Tags otp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/otp/mail/enable [put]
func MailOTPEnable(c *gin.Context) {
	var request mailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Enable Mail OTP
	rowsAffected, errCode, errMailOTPUpdateEnabled := mariadb.MailOTPUpdateEnabled(request.Mail, true)
	if errMailOTPUpdateEnabled != nil {
		switch errCode {
		case 1002:
			errorMessage := fmt.Sprintf("Failed to execute SQL syntax: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return

		case 1049:
			errorMessage := fmt.Sprintf("Get rowsAffected failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return
		}
	}

	// No rows were affected
	if rowsAffected == 0 {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail": request.Mail,
			"msg":  "No rows were affected.",
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":             request.Mail,
			"mail_otp_enabled": true,
		}))
	}
}

// @Summary Mail OTP Disable
// @Description Disable Mail OTP feature
// @Tags otp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/otp/mail/disable [put]
func MailOTPDisable(c *gin.Context) {
	var request mailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Disable Mail OTP
	rowsAffected, errCode, errMailOTPUpdateEnabled := mariadb.MailOTPUpdateEnabled(request.Mail, false)
	if errMailOTPUpdateEnabled != nil {
		switch errCode {
		case 1002:
			errorMessage := fmt.Sprintf("Failed to execute SQL syntax: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return

		case 1049:
			errorMessage := fmt.Sprintf("Get rowsAffected failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
			return
		}
	}

	// No rows were affected
	if rowsAffected == 0 {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail": request.Mail,
			"msg":  "No rows were affected.",
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":             request.Mail,
			"mail_otp_enabled": false,
		}))
	}

}

// @Summary Mail OTP Send
// @Description To send an OTP using email.
// @Tags otp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/otp/mail/send [post]
func MailOTPSend(c *gin.Context) {
	var request mailOperate
	var user string

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userInfo, err := mariadb.GetUserInfo(request.Mail)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1048, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	// Mail user name decision logic
	if userInfo.FirstName.Valid && userInfo.FirstName.String != "" {
		user = userInfo.FirstName.String
	} else if userInfo.Username.Valid && userInfo.Username.String != "" {
		user = userInfo.Username.String
	} else {
		re := regexp.MustCompile(`([^@]+)@`)
		match := re.FindStringSubmatch(userInfo.Mail)
		if len(match) > 1 {
			user = match[1]
		} else {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1054, err))
			return
		}
	}

	code := encrypt.RandomNumber(6)

	redisTTL, _, err := time_convert.ConvertTimeFormat("1h")
	if err != nil {
		if err != nil {
			errorMessage := fmt.Sprintf("TTL string convert to duration failed: %v", err)
			slog.Error(errorMessage)
			panic(err)
		}
	}

	redisKey := encrypt.HashWithSHA(request.Mail, "sha1")

	err = redis.Set("mail_otp:"+redisKey, code, redisTTL)

	if err != nil {
		errorMessage := fmt.Sprintf("Redis SET data failed.: %v", err)
		slog.Error(errorMessage)
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1042, err))
		return
	}

	errSendMailOTP := smtp.SendMailOTP(c, user, userInfo.Mail, code)
	if errSendMailOTP != nil {
		slog.Error(errSendMailOTP.Error())
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary Mail OTP Verify
// @Description If a user has enabled Mail OTP, the API can be used during the login process to verify its validity.
// @Tags otp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param otp_code formData string false "OTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/otp/mail/verify [get]
func MailOTPVerify(c *gin.Context) {
	var data rdsValeData

	mail, isMailExists := c.Get("mail")
	userName, isUserNameExists := c.Get("userName")
	Result, isMailOTPVerifyExists := c.Get("mail_otp_verify")

	// Convert interface to string
	strMail := fmt.Sprintf("%v", mail)

	if !isMailExists || !isMailOTPVerifyExists || !isUserNameExists {
		slog.Error("mail, mail_otp_verify or username are not exists.")
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1052, nil))
		return
	}

	verifyResult, ok := Result.(bool)
	if !ok {
		slog.Error("OTP verify result value is not bool.")
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1051, nil))
		return
	}

	if verifyResult {
		// Check whether login status exists in redis or not.
		value, errCode, err := redis.Get("login_status:" + strMail)

		switch errCode {
		// Key not exists
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
		// Key exists
		case 0:
			err := json.Unmarshal([]byte(value), &data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1063, err))
				return
			}

			// Change status
			data.MailOTPPassed = true

			jsonData, err := json.Marshal(data)
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
			err = redis.Set("login_status:"+strMail, string(jsonData), redisTTL)

			if err != nil {
				errorMessage := fmt.Sprintf("Redis SET data failed.: %v", err)
				slog.Error(errorMessage)
				c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1042, err))
				return
			}
		}

		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":            strMail,
			"username":        userName,
			"mail_otp_verify": true,
		}))
	} else {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1047, map[string]interface{}{
			"mail":            strMail,
			"username":        userName,
			"mail_otp_verify": false,
		}))
	}

}
