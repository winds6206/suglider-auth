package otp

import (
	"suglider-auth/pkg/api-server/api_v1/handlers"

	"github.com/gin-gonic/gin"
)

func OtpHandler(router *gin.RouterGroup) {

	router.PUT("/mail-enable", handlers.MailOTPenable)
	router.PUT("/mail-disable", handlers.MailOTPdisable)

	router.POST("/mail-send", handlers.MailOTP)
	router.GET("/mail-verify", handlers.MailOTPverify)
}
