package rbac

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

type CasbinEnforcerConfig = handlers.CasbinEnforcerConfig

func RbacHandlers(router *gin.RouterGroup, csbn *CasbinEnforcerConfig) {
	router.GET("/roles", handlers.CasbinListRoles(csbn))
	router.GET("/members", handlers.CasbinListMembers(csbn))
	router.GET("/role/:name", handlers.CasbinGetMembersWithRole(csbn))
	router.GET("/member/:name", handlers.CasbinGetRolesOfMember(csbn))
	router.POST("/rbac/policy/add", handlers.CasbinAddPolicy(csbn))
	router.POST("/rbac/grouping/add", handlers.CasbinAddGroupingPolicy(csbn))
	router.POST("/rbac/policy/delete", handlers.CasbinDeleteSinglePolicy(csbn))
	router.POST("/rbac/policy/:name/delete", handlers.CasbinDeletePolicy(csbn))
	router.POST("/rbac/grouping/:name/delete", handlers.CasbinDeleteGroupingPolicy(csbn))
}
