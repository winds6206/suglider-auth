package rbac

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

type CasbinConfig = handlers.CasbinConfig

func RbacHandlers(router *gin.RouterGroup, csbn *CasbinConfig) {
	router.GET("/roles", handlers.CasbinListRoles(csbn))
	router.GET("/members", handlers.CasbinListMembers(csbn))
	router.GET("/role/:name", handlers.CasbinGetRole(csbn))
	router.GET("/member/:name", handlers.CasbinGetMember(csbn))
	router.POST("/rbac/policy/add", handlers.CasbinAddPolicy(csbn))
	router.POST("/rbac/grouping/add", handlers.CasbinAddGroupingPolicy(csbn))
	router.POST("/rbac/policy/:name/delete", handlers.CasbinDeletePolicy(csbn))
	router.POST("/rbac/grouping/:name/delete", handlers.CasbinDeleteGroupingPolicy(csbn))
}
