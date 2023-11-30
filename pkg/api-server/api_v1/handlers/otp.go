package handlers

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
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
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-enable [put]
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
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-disable [put]
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
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-send [post]
func MailOTPSend(c *gin.Context) {
	var request mailOperate

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

	redis.Set("mail_otp:"+redisKey, code, redisTTL)

	errSendMailOTP := smtp.SendMailOTP(c, userInfo.FirstName, userInfo.Mail, code)
	if errSendMailOTP != nil {
		slog.Error(errSendMailOTP.Error())
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary Mail OTP Verify
// @Description If a user has enabled Mail OTP, the API can be used during the login process to verify its validity.
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param otpCode formData string false "OTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-verify [get]
func MailOTPVerify(c *gin.Context) {
	mail, isMailExists := c.Get("mail")
	Result, isMailOTPVerifyExists := c.Get("mail_otp_verify")

	if !isMailExists || !isMailOTPVerifyExists {
		slog.Error("mail and mail_otp_verify are not exists.")
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
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"mail":            mail,
			"mail_otp_verify": true,
		}))
	} else {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1047, map[string]interface{}{
			"mail":            mail,
			"mail_otp_verify": false,
		}))
	}

}
