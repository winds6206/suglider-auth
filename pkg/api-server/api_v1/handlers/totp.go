package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"
	mariadb "suglider-auth/internal/database"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/totp"

	"github.com/gin-gonic/gin"
)

type totpInput struct {
	Mail    string `json:"mail"`
	OTPCode string `json:"otp_code"`
}

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
	var request totpInput

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

	var request totpInput

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

	mail, isMailExists := c.Get("mail")
	Result, isTOTPVerifyExists := c.Get("totp_verify")

	if !isMailExists || !isTOTPVerifyExists {
		slog.Error("mail and totp_verify are not exists.")
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
			"mail":        mail,
			"totp_verify": true,
		}))
	} else {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1047, map[string]interface{}{
			"mail":        mail,
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
	var request totpInput

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
