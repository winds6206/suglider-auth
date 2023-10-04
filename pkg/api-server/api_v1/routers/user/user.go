package user

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

func UserHandler(router *gin.RouterGroup) {

	router.POST("/sign-up", handlers.UserSignUp)

}
