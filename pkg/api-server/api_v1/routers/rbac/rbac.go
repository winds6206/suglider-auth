package rbac

import (
	"suglider-auth/pkg/api-server/api_v1/handlers"

	"github.com/gin-gonic/gin"
)

type CasbinEnforcerConfig = handlers.CasbinEnforcerConfig

func RbacHandlers(router *gin.RouterGroup, csbn *CasbinEnforcerConfig) {
	router.GET("/policies", handlers.CasbinListPolicies(csbn))
	router.GET("/roles", handlers.CasbinListRoles(csbn))
	router.GET("/members", handlers.CasbinListMembers(csbn))
	router.GET("/role/:role", handlers.CasbinGetMembersWithRole(csbn))
	router.GET("/member/:member", handlers.CasbinGetRolesOfMember(csbn))
	router.POST("/policy/add", handlers.CasbinAddPolicy(csbn))
	router.POST("/grouping/add", handlers.CasbinAddGroupingPolicy(csbn))
	router.DELETE("/policy/delete", handlers.CasbinDeleteSinglePolicy(csbn))
	router.DELETE("/grouping/delete", handlers.CasbinDeleteSingleGroupingPolicy(csbn))
	router.DELETE("/policy/:role/delete", handlers.CasbinDeletePolicy(csbn))
	router.DELETE("/grouping/:member/delete", handlers.CasbinDeleteGroupingPolicy(csbn))
}
