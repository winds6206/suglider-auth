package totp

import (
	"suglider-auth/pkg/api-server/api_v1/handlers"

	"github.com/gin-gonic/gin"
)

func TotpHandler(router *gin.RouterGroup) {

	router.POST("/generate", handlers.TotpGenerate)
	router.PATCH("/verify", handlers.TotpVerify)
	router.POST("/validate", handlers.ValidateTOTP(), handlers.TotpValidate)
	router.PUT("/disable", handlers.TotpDisable)
}
