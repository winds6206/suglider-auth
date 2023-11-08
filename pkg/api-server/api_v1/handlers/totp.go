package handlers

import (
	"database/sql"
	"net/http"
	"github.com/gin-gonic/gin"
	mariadb "suglider-auth/internal/database"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/totp"
	"suglider-auth/pkg/session"
)

type totpInput struct {
	Username string `json:"username"`
	TotpCode string `json:"totpCode"`
}

// @Summary Enable TOTP
// @Description generate QRcode
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/generate [post]
func TotpGenerate(c *gin.Context) {
	var request *totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Look up user ID
	userIDInfo, err := mariadb.LookupUserID(request.Username)
	if err != nil {
        if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
    }

	// Generate TOTP QRcode
	totpInfo, imageData, errCode, err := totp.TotpGernate(request.Username, userIDInfo.UserID)
	if errCode != 0 {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
	}
	c.Header("Content-Type", "image/png")
	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, totpInfo))
	c.Data(http.StatusOK, "image/png", imageData)
}

// @Summary Verify TOTP
// @Description The API uses the first enabled TOTP feature to verify the TOTP code.
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param username formData string false "TOTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/generate [post]

// The API uses the first enabled TOTP feature to verify the TOTP code.
func TotpVerify(c *gin.Context) {

	var request totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// To get TOTP secret
	totpData, err := mariadb.TotpUserData(request.Username)
	if err != nil {
        if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
    }

	// Verify TOTP Code from user input
	valid := totp.TotpValidate(request.TotpCode, totpData.TotpSecret)

	if !valid {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1007))
		return
	}

	// Update TOTP enabled and verified column status in database
	errTotpUpdateVerify := mariadb.TotpUpdateVerify(request.Username, true, true)
	if errTotpUpdateVerify != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary Verify TOTP Validate
// @Description If a user has enabled TOTP, the API can be used during the login process to verify its validity.
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param username formData string false "TOTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/generate [post]

// If a user has enabled TOTP, the API can be used during the login process to verify its validity.
func TotpValidate(c *gin.Context) {

	var request totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// To get TOTP secret
	totpData, err := mariadb.TotpUserData(request.Username)
	if err != nil {
        if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006, err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
    }

	// Verify TOTP Code from user input
	valid := totp.TotpValidate(request.TotpCode, totpData.TotpSecret)

	if !valid {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1007))
		return
	}

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

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))

}

// @Summary Disable TOTP
// @Description disable TOTP
// @Tags users
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/generate [post]
func TotpDisable(c *gin.Context) {
	var request totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// Update TOTP enabled column status in database
	errTotpUpdateEnabled := mariadb.TotpUpdateEnabled(request.Username, false)
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