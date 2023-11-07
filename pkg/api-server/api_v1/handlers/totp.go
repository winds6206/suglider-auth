package handlers

import (
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

func TotpGenerate(c *gin.Context) {
	var request *totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userIDInfo, err := mariadb.LookupUserID(request.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	if userIDInfo.UserID == "" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006))
		return
	}

	totpInfo, imageData := totp.TotpGernate(request.Username, userIDInfo.UserID)
	c.Header("Content-Type", "image/png")
	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, totpInfo))
	c.Data(http.StatusOK, "image/png", imageData)
}

func TotpVerify(c *gin.Context) {

	var request totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userIDInfo, err := mariadb.LookupUserID(request.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	if userIDInfo.UserID == "" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006))
		return
	}

	totpData, _ := mariadb.TotpUserData(userIDInfo.UserID, request.Username)

	valid := totp.TotpValidate(request.TotpCode, totpData.TotpSecret)

	if !valid {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1007))
		return
	}

	errTotpUpdateVerify := mariadb.TotpUpdateVerify(userIDInfo.UserID, request.Username, true, true)
	if errTotpUpdateVerify != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

func TotpValidate(c *gin.Context) {

	var request totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userIDInfo, err := mariadb.LookupUserID(request.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	if userIDInfo.UserID == "" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006))
		return
	}

	totpData, _ := mariadb.TotpUserData(userIDInfo.UserID, request.Username)

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

func TotpDisable(c *gin.Context) {
	var request totpInput

	// Check the parameter trasnfer from POST
	err := c.ShouldBindJSON(&request)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	userIDInfo, err := mariadb.LookupUserID(request.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	if userIDInfo.UserID == "" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1006))
		return
	}

	errTotpUpdateEnabled := mariadb.TotpUpdateEnabled(userIDInfo.UserID, request.Username, false)
	if errTotpUpdateEnabled != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1002, err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))

}