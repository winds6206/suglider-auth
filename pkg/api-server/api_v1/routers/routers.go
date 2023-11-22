package routers

import (
	"suglider-auth/pkg/api-server/api_v1/routers/otp"
	"suglider-auth/pkg/api-server/api_v1/routers/rbac"
	"suglider-auth/pkg/api-server/api_v1/routers/totp"
	"suglider-auth/pkg/api-server/api_v1/routers/user"

	"github.com/gin-gonic/gin"
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
	totpRouter := router.Group("/totp")
	{
		totp.TotpHandler(totpRouter)
	}
	otpRouter := router.Group("/otp")
	{
		otp.OtpHandler(otpRouter)
	}
}
