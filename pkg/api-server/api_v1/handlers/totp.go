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
	"suglider-auth/pkg/time_convert"
	"suglider-auth/pkg/totp"

	"github.com/gin-gonic/gin"
)

// @Summary Enable TOTP
// @Description generate QRcode
// @Tags totp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/generate [post]
func TotpGenerate(c *gin.Context) {
	var request mailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Look up user ID
	userIDInfo, err := mariadb.LookupUserID(request.Mail)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	// Generate TOTP QRcode
	totpInfo, imageData, errCode, err := totp.TotpGernate(request.Mail, userIDInfo.UserID)
	if errCode != 0 {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
	}
	c.Header("Content-Type", "image/png")
	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, totpInfo))
	c.Data(http.StatusOK, "image/png", imageData)
}

// @Summary Verify TOTP
// @Description The API uses the first enabled TOTP feature to verify the TOTP code.
// @Tags totp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param otp_code formData string false "OTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/verify [patch]
func TotpVerify(c *gin.Context) {
	// The API uses the first enabled TOTP feature to verify the TOTP code.

	var request otpData

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// To get TOTP secret
	totpData, err := mariadb.TotpUserData(request.Mail)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	// Verify TOTP Code from user input
	valid := totp.TotpValidate(request.OTPCode, totpData.TotpSecret)

	if !valid {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1007))
		return
	}

	// Update TOTP enabled and verified column status in database
	errTotpUpdateVerify := mariadb.TotpUpdateVerify(request.Mail, true, true)
	if errTotpUpdateVerify != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary Verify TOTP Validate
// @Description If a user has enabled TOTP, the API can be used during the login process to verify its validity.
// @Tags totp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Param otp_code formData string false "OTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/validate [post]
func TotpValidate(c *gin.Context) {

	var data rdsValeData

	mail, isMailExists := c.Get("mail")
	userName, isUserNameExists := c.Get("userName")
	Result, isTOTPVerifyExists := c.Get("totp_verify")

	// Convert interface to string
	strMail := fmt.Sprintf("%v", mail)

	if !isMailExists || !isTOTPVerifyExists || !isUserNameExists {
		slog.Error("mail, totp_verify or username are not exists.")
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1071, nil))
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
			"mail":        strMail,
			"username":    userName,
			"totp_verify": true,
		}))
	} else {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1047, map[string]interface{}{
			"mail":        strMail,
			"username":    userName,
			"totp_verify": false,
		}))
	}
}

// @Summary Disable TOTP
// @Description disable TOTP
// @Tags totp
// @Accept multipart/form-data
// @Produce application/json
// @Param mail formData string false "Mail"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/disable [put]
func TotpDisable(c *gin.Context) {
	var request mailOperate

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Update TOTP enabled column status in database
	errTotpUpdateEnabled := mariadb.TotpUpdateEnabled(request.Mail, false)
	if errTotpUpdateEnabled != nil {
		if errTotpUpdateEnabled == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, errTotpUpdateEnabled))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, errTotpUpdateEnabled))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))

}
