package user

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

func UserHandler(router *gin.RouterGroup) {

	router.POST("/sign-up", handlers.UserSignUp)
	router.POST("/delete", handlers.UserDelete)
	router.POST("/login", handlers.UserLogin)
	router.POST("/logout", handlers.UserLogout)
	router.POST("/password-expire", handlers.PasswordExpire)
	router.POST("/password-extension", handlers.PasswordExtension)
	router.GET("/refresh", handlers.RefreshJWT)
	router.POST("/verify-mail", handlers.VerifyEmailAddress)
	router.GET("/verify-mail/resend", handlers.ResnedVerifyEmail)

	// Test
	router.GET("/test-logout", handlers.TestLogout)
	router.POST("/test-login", handlers.TestLogin)
	router.GET("/test-welcome", handlers.TestWelcome)
	router.GET("/test-refresh", handlers.TestRefresh)
}
