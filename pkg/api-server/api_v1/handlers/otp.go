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

type mailOTPverifyData struct {
	UserName string `json:"username" binding:"required"`
	OTPcode  string `json:"otp_code" binding:"required"`
}

// @Summary Mail OTP Enable
// @Description Enable Mail OTP feature
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-enable [put]
func MailOTPenable(c *gin.Context) {
	var request userNameOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Enable Mail OTP
	rowsAffected, errCode, errMailOTPupdateEnabled := mariadb.MailOTPupdateEnabled(request.UserName, true)
	if errMailOTPupdateEnabled != nil {
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
			"username": request.UserName,
			"msg":      "No rows were affected.",
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username":         request.UserName,
			"mail_otp_enabled": true,
		}))
	}
}

// @Summary Mail OTP Disable
// @Description Disable Mail OTP feature
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-disable [put]
func MailOTPdisable(c *gin.Context) {
	var request userNameOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Disable Mail OTP
	rowsAffected, errCode, errMailOTPupdateEnabled := mariadb.MailOTPupdateEnabled(request.UserName, false)
	if errMailOTPupdateEnabled != nil {
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
			"username": request.UserName,
			"msg":      "No rows were affected.",
		}))
	} else {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username":         request.UserName,
			"mail_otp_enabled": false,
		}))
	}

}

// @Summary Mail OTP Send
// @Description To send an OTP using email.
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-send [post]
func MailOTP(c *gin.Context) {
	var request userNameOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userMail, err := mariadb.GetUserMail(request.UserName)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1048, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	//TODO
	fmt.Println(userMail.Mail)

	code := encrypt.RandomNumber(6)

	redisTTL, _, err := time_convert.ConvertTimeFormat("1h")
	if err != nil {
		if err != nil {
			errorMessage := fmt.Sprintf("TTL string convert to duration failed: %v", err)
			slog.Error(errorMessage)
			panic(err)
		}
	}

	redisKey := encrypt.HashWithSHA(request.UserName, "sha1")

	redis.Set("mail_otp:"+redisKey, code, redisTTL)
	fmt.Println(code)

	errSendMailOTP := smtp.SendMailOTP(c, request.UserName, "winds6206@gmail.com", code)
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
// @Param username formData string false "User Name"
// @Param otpCode formData string false "OTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/mail-verify [get]
func MailOTPverify(c *gin.Context) {
	var request mailOTPverifyData

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	redisKey := encrypt.HashWithSHA(request.UserName, "sha1")

	value, errCode, err := redis.Get("mail_otp:" + redisKey)

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
	}

	if value == request.OTPcode {
		c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, map[string]interface{}{
			"username":   request.UserName,
			"otp_verify": true,
		}))

	} else {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1047, map[string]interface{}{
			"username":   request.UserName,
			"otp_verify": false,
		}))
	}
}
