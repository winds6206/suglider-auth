package routers

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/routers/user"
	"suglider-auth/pkg/api-server/api_v1/routers/rbac"
)

type CasbinEnforcerConfig = rbac.CasbinEnforcerConfig

func Apiv1Handler(router *gin.RouterGroup, csbn *CasbinEnforcerConfig) {
	userRouter := router.Group("/user")
	{
		user.UserHandler(userRouter)
	}
	rbacRouter := router.Group("/rbac")
	{
		rbac.RbacHandlers(rbacRouter, csbn)
	}
}
