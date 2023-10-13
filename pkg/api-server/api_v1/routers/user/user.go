package user

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

func UserHandler(router *gin.RouterGroup) {

	router.POST("/sign-up", handlers.UserSignUp)
	router.POST("/delete", handlers.UserDelete)
	router.POST("/login", handlers.UserLogin)
	router.POST("/logout", handlers.UserLogOut)

	// Test
	router.GET("/test", handlers.Test)
	router.GET("/test-v2", handlers.Testv2)
}
