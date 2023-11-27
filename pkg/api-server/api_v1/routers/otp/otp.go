package otp

import (
	"suglider-auth/pkg/api-server/api_v1/handlers"

	"github.com/gin-gonic/gin"
)

func OtpHandler(router *gin.RouterGroup) {

	router.PUT("/mail-enable", handlers.MailOTPEnable)
	router.PUT("/mail-disable", handlers.MailOTPDisable)
	router.POST("/mail-send", handlers.MailOTPSend)
	router.GET("/mail-verify", handlers.ValidateMailOTP(), handlers.MailOTPVerify)
}
