package rbac

import (
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/api-server/api_v1/handlers"
)

type CasbinEnforcerConfig = handlers.CasbinEnforcerConfig

func RbacHandlers(router *gin.RouterGroup, csbn *CasbinEnforcerConfig) {
	router.GET("/policies", handlers.CasbinListPolicies(csbn))
	router.GET("/roles", handlers.CasbinListRoles(csbn))
	router.GET("/members", handlers.CasbinListMembers(csbn))
	router.GET("/role/:name", handlers.CasbinGetMembersWithRole(csbn))
	router.GET("/member/:name", handlers.CasbinGetRolesOfMember(csbn))
	router.POST("/policy/add", handlers.CasbinAddPolicy(csbn))
	router.POST("/grouping/add", handlers.CasbinAddGroupingPolicy(csbn))
	router.DELETE("/policy/delete", handlers.CasbinDeleteSinglePolicy(csbn))
	router.DELETE("/grouping/delete", handlers.CasbinDeleteSingleGroupingPolicy(csbn))
	router.DELETE("/policy/:name/delete", handlers.CasbinDeletePolicy(csbn))
	router.DELETE("/grouping/:name/delete", handlers.CasbinDeleteGroupingPolicy(csbn))
}
