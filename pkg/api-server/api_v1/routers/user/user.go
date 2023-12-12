package user

import (
	"suglider-auth/pkg/api-server/api_v1/handlers"

	"github.com/gin-gonic/gin"
)

func UserHandler(router *gin.RouterGroup) {

	router.POST("/sign-up", handlers.UserSignUp)
	router.DELETE("/delete", handlers.UserDelete)
	router.POST("/login", handlers.LoginStatusCheck(), handlers.UserLogin)
	router.POST("/logout", handlers.UserLogout)
	router.GET("/password-expire", handlers.PasswordExpire)
	router.PATCH("/password-extension", handlers.PasswordExtension)
	router.GET("/refresh", handlers.RefreshJWT)
	router.POST("/verify-mail", handlers.VerifyEmailAddress)
	router.GET("/verify-mail/resend", handlers.ResendVerifyEmail)
	router.GET("/forgot-password", handlers.ForgotPasswordEmail)
	router.POST("/reset-password", handlers.RestUserPassword)
	router.GET("/check-username", handlers.CheckUserName)
	router.GET("/check-mail", handlers.CheckMail)
	router.PATCH("/change-password", handlers.ChangePassword)
	router.PATCH("/setup-password", handlers.SetUpPassword)
	router.PUT("/update-personal-info", handlers.UpdatePersonalInfo)
}
