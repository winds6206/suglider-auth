package handlers

import (
	"log/slog"
	"net/http"
	"github.com/gin-gonic/gin"
	smtp "suglider-auth/internal/mail"
	"suglider-auth/internal/utils"
)

type userMail struct {
	Username  string
	Mail      string
}

// @Summary Verify Email
// @Description verify email address for user
// @Tags users
// @Accept application/json
// @Produce application/json
// @Param mail query string false "Email"
// @Param verifyId query string false "Verify ID"
// @Param verifyCode query string false "Verify Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/verify-mail [post]
func VerifyEmailAddress(c *gin.Context) {
	mail := c.Query("name")
	verifyId := c.Query("verifyId")
	verifyCode := c.Query("verifyCode")

	pass, err := smtp.VerifyUserMail(c, mail, verifyId, verifyCode)
	if pass && err == nil {
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"mail": mail,
			}),
		)
		return
	} else if pass && err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1022, err))
	}
	c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1023, err))
}

// @Summary Resend Verify Email
// @Description Resem a mail to verify email address for user
// @Tags users
// @Accept application/json
// @Produce application/json
// @Param username query string false "Username"
// @Param mail query string false "Email"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/verify-mail/resend [post]
func ResnedVerifyEmail(c *gin.Context) {
	var err error
	if err = c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}
	postData := &userMail{}
	if err = c.Bind(&postData); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1001, err))
		return
	}

	// send mail
	if err = smtp.SendVerifyMail(c, postData.Username, postData.Mail); err != nil {
		slog.Error(err.Error())
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}
