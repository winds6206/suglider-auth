package totp

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

func TotpHandler(router *gin.RouterGroup) {

	router.POST("/generate", handlers.TotpGenerate)
	router.POST("/verify", handlers.TotpVerify)
	router.POST("/validate", handlers.TotpValidate)
	router.POST("/disable", handlers.TotpDisable)
}
