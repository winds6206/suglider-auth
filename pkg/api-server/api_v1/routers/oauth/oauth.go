package oauth

import (
	"suglider-auth/pkg/api-server/api_v1/handlers"

	"github.com/gin-gonic/gin"
)

func OAuthHandler(router *gin.RouterGroup) {

	router.GET("/google/login", handlers.OAuthGoogleLogin)
	router.GET("/google/sign-up", handlers.OAuthGoogleSignUp)
	router.GET("/google/callback", handlers.OAuthGoogleCallback)
	router.POST("/google/verify", handlers.OAuthGoogleVerification)
}
