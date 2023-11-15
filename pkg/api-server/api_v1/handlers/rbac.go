package handlers

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	csbn "suglider-auth/pkg/rbac"
	"suglider-auth/internal/utils"
)

type (
	CasbinEnforcerConfig = csbn.CasbinEnforcerConfig
	CasbinPolicy         = csbn.CasbinPolicy
	CasbinGroupingPolicy = csbn.CasbinGroupingPolicy
	CasbinObject         = csbn.CasbinObject
)

// @Summary List All Policies
// @Description show all policies defined in the server
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/policies [get]
func CasbinListPolicies(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		policies := csbn.ListRoles()
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"policies": policies,
			}),
		)
	}
}

// @Summary List All Roles
// @Description show all roles defined in the server
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/roles [get]
func CasbinListRoles(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles := csbn.ListRoles()
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"roles": roles,
			}),
		)
	}
}

// @Summary List All Members
// @Description show all members defined in the server
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/members [get]
func CasbinListMembers(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		members := csbn.ListMembers()
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"members": members,
			}),
		)
	}
}

// @Summary Get Members With Role
// @Description show all members with this role
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Role Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/role/{name} [get]
func CasbinGetMembersWithRole(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1103, err))
			return
		}
		members, err := csbn.GetMembersWithRole(name)
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1028, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"members": members,
			}),
		)
	}
}

// @Summary Get Roles of Member
// @Description show all roles attached to this member
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Member Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/member/{name} [get]
func CasbinGetRolesOfMember(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1103, err))
			return
		}
		roles, err := csbn.GetRolesOfMember(name)
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1029, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"roles": roles,
			}),
		)
	}
}

// @Summary Add RBAC Policy
// @Description new a role/policy
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param subject formData string false "Subject"
// @Param object formData string false "Object"
// @Param action formData string false "Action"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/policy/add [post]
func CasbinAddPolicy(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		if err = c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1101, err))
			return
		}
		postData := &CasbinPolicy{}
		if err = c.Bind(&postData); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1102, err))
			return
		}
		if postData.Sub == "" || postData.Obj == "" || postData.Act == "" {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1104))
			return
		}
		if err = csbn.AddPolicy(postData); err != nil {
			if err.Error() == "This policy already exists." {
				c.JSON(
					http.StatusOK,
					utils.SuccessResponse(c, 200, map[string]interface{} {
						"event":   "nothing happens",
						"warning": "This policy already exists.",
						"subject": postData.Sub,
						"object":  postData.Obj,
						"action":  postData.Act,
					}),
				)
				return
			}
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1030, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"subject": postData.Sub,
				"object":  postData.Obj,
				"action":  postData.Act,
			}),
		)
	}
}

// @Summary Add RBAC Grouping Policy
// @Description new a group (member-role) policy
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param member formData string false "Member"
// @Param role formData string false "Role"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/grouping/add [post]
func CasbinAddGroupingPolicy(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		if err = c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1101, err))
			return
		}
		postData := &CasbinGroupingPolicy{}
		if err = c.Bind(&postData); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1102, err))
			return
		}
		if postData.Member == "" || postData.Role == "" {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1104))
			return
		}
		if err = csbn.AddGroupingPolicy(postData); err != nil {
			if err.Error() == "This grouping policy already exists." {
				c.JSON(
					http.StatusOK,
					utils.SuccessResponse(c, 200, map[string]interface{} {
						"event":   "nothing happens",
						"warning": "This grouping policy already exists.",
						"member":  postData.Member,
						"role":    postData.Role,
					}),
				)
				return
			}
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1031, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"member":  postData.Member,
				"role":    postData.Role,
			}),
		)
	}
}

// @Summary Delete RBAC Single Policy
// @Description delete a single policy
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param subject formData string false "Subject"
// @Param object formData string false "Object"
// @Param action formData string false "Action"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/policy/delete [delete]
func CasbinDeleteSinglePolicy(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		if err = c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1101, err))
			return
		}
		postData := &CasbinPolicy{}
		if err = c.Bind(&postData); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1102, err))
			return
		}
		if postData.Sub == "" || postData.Obj == "" || postData.Act == "" {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1104))
			return
		}
		if err = csbn.DeletePolicy(postData); err != nil {
			if err.Error() == "This policy not exists." {
				c.JSON(
					http.StatusOK,
					utils.SuccessResponse(c, 200, map[string]interface{} {
						"event":   "nothing happens",
						"warning": "This policy not exists.",
						"subject": postData.Sub,
						"object":  postData.Obj,
						"action":  postData.Act,
					}),
				)
				return
			}
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1032, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"subject": postData.Sub,
				"object":  postData.Obj,
				"action":  postData.Act,
			}),
		)
	}
}

// @Summary Delete RBAC Single Grouping Policy (Remove A Role of Member)
// @Description delete a single policy (remove a role of member)
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param member formData string false "Member"
// @Param role formData string false "Role"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/grouping/delete [delete]
func CasbinDeleteSingleGroupingPolicy(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		if err = c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1101, err))
			return
		}
		postData := &CasbinGroupingPolicy{}
		if err = c.Bind(&postData); err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1102, err))
			return
		}
		if postData.Member == "" || postData.Role == "" {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1104))
			return
		}
		if err = csbn.DeleteGroupingPolicy(postData); err != nil {
			if err.Error() == "This grouping policy not exists." {
				c.JSON(
					http.StatusOK,
					utils.SuccessResponse(c, 200, map[string]interface{} {
						"event":   "nothing happens",
						"warning": "This grouping policy not exists.",
						"member":  postData.Member,
						"role":    postData.Role,
					}),
				)
				return
			}
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1033, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"member":  postData.Member,
				"role":    postData.Role,
			}),
		)
	}
}

// @Summary Delete RBAC Policy (Role)
// @Description delete a policy (role)
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Role Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/policy/{name}/delete [delete]
func CasbinDeletePolicy(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1103, err))
			return
		}
		if err = csbn.DeleteRole(name); err != nil {
			if err.Error() == "This policy (role) not exists." {
				c.JSON(
					http.StatusOK,
					utils.SuccessResponse(c, 200, map[string]interface{} {
						"event":   "nothing happens",
						"warning": "This policy (role) not exists.",
						"role":    name,
					}),
				)
				return
			}
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1034, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"role":    name,
			}),
		)
	}
}

// @Summary Delete RBAC Grouping Policy (Member)
// @Description Delete all roles associated with a specified member
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Member Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/grouping/{name}/delete [delete]
func CasbinDeleteGroupingPolicy(csbn *CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1103, err))
			return
		}
		if err = csbn.DeleteMemeber(name); err != nil {
			if err.Error() == "This groupiing policy (member) not exists." {
				c.JSON(
					http.StatusOK,
					utils.SuccessResponse(c, 200, map[string]interface{} {
						"event":   "nothing happens",
						"warning": "This groupiing policy (member) not exists.",
						"member":  name,
					}),
				)
				return
			}
			c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, 1035, err))
			return
		}
		c.JSON(
			http.StatusOK,
			utils.SuccessResponse(c, 200, map[string]interface{} {
				"member":    name,
			}),
		)
	}
}
