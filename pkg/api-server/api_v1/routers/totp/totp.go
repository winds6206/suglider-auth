package totp

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

func TotpHandler(router *gin.RouterGroup) {

	router.POST("/generate", handlers.TotpGenerate)
	router.PATCH("/verify", handlers.TotpVerify)
	router.POST("/validate", handlers.TotpValidate)
	router.PUT("/disable", handlers.TotpDisable)
}
