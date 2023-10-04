package routers

import (
	"github.com/gin-gonic/gin"
    "suglider-auth/pkg/api-server/api_v1/routers/user"

)

func Apiv1Handler(router *gin.RouterGroup) {
	userRouter := router.Group("/user")
	{
		user.UserHandler(userRouter)
	}
}