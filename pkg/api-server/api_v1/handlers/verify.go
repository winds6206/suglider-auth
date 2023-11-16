package handlers

import (
	"log/slog"
	"net/http"
	"fmt"
	"github.com/gin-gonic/gin"

	smtp "suglider-auth/internal/mail"
	db "suglider-auth/internal/database"
	pwv "suglider-auth/pkg/pwd-validator"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/encrypt"
)

type passwordReset struct {
	Password  string   `json:"password"`
}

// @Summary Verify Email Address
// @Description verify email address for user
// @Tags users
// @Accept application/json
// @Produce application/json
// @Param mail query string false "Email"
// @Param verify-id query string false "Verify ID"
// @Param verify-code query string false "Verify Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/verify-mail [post]
func VerifyEmailAddress(c *gin.Context) {
	mail := c.Query("mail")
	verifyId := c.Query("verify-id")
	verifyCode := c.Query("verify-code")

	pass, err := smtp.VerifyUserMailAddress(c, mail, verifyId, verifyCode)
	if pass && err == nil {
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"mail": mail,
			}),
		)
		return
	} else if pass && err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1023, err))
	}

	c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1024, err))
}

// @Summary Resend Verify Email
// @Description Resend a mail to verify email address for user
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
// @Router /api/v1/user/verify-mail/resend [get]
func ResendVerifyEmail(c *gin.Context) {
	user := c.Query("username")
	mail := c.Query("mail")

	if err := smtp.SendVerifyMail(c, user, mail); err != nil {
		slog.Error(err.Error())
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1022, err))
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary Send Password Reset Email
// @Description Send a mail to reset password
// @Tags users
// @Accept application/json
// @Produce application/json
// @Param mail query string false "Email"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/forgot-password [get]
func ForgotPasswordEmail(c *gin.Context) {
	mail := c.Query("mail")

	if err := smtp.SendPasswordResetMail(c, mail); err != nil {
		slog.Error(err.Error())
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1025, err))
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(c, 200, nil))
}

// @Summary Reset Password
// @Description reset password for user
// @Tags users
// @Accept application/json
// @Produce application/json
// @Param password formData string false "New Password"
// @Param mail query string false "Email"
// @Param reset-id query string false "Reset ID"
// @Param reset-code query string false "Reset Code"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/user/reset-password [post]
func RestUserPassword(c *gin.Context) {
	var err error
	if err = c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1101, err))
		return
	}
	postData := &passwordReset{}
	if err = c.Bind(&postData); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1102, err))
		return
	}
	mail := c.Query("mail")
	resetId := c.Query("reset-id")
	resetCode := c.Query("reset-code")

	errPwdValidator := pwv.PwdValidator("ignoreThis", postData.Password, "this@ignore.here")
	if errPwdValidator != nil {

		errorMessage := fmt.Sprintf("%v", errPwdValidator)
		slog.Error(errorMessage)
		
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1021, errPwdValidator))
		return
	}

	pass, err := smtp.CheckPasswordResetCode(c, mail, resetId, resetCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1026, err))
		return
	}

	if pass {
		pwd, _ := encrypt.SaltedPasswordHash(postData.Password)
		if err = db.UserResetPassword(c, mail, pwd); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1027, err))
			return
		}
	}

	c.JSON(
		http.StatusOK,
		utils.SuccessResponse(c, 200, map[string]interface{} {
			"mail": mail,
		}),
	)
}
