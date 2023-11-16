package handlers

import (
	"database/sql"
	"net/http"
	"log/slog"
	"fmt"
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
// @Tags totp
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
// @Tags totp
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param totpCode formData string false "TOTP Code"
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
// @Tags totp
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
// @Param totpCode formData string false "TOTP Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/totp/validate [post]
func TotpValidate(c *gin.Context) {
// If a user has enabled TOTP, the API can be used during the login process to verify its validity.

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
c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))

}

// @Summary Disable TOTP
// @Description disable TOTP
// @Tags totp
// @Accept multipart/form-data
// @Produce application/json
// @Param username formData string false "User Name"
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