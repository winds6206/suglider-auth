package handlers

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"net/url"
	mariadb "suglider-auth/internal/database"
)

type CasbinConfig struct {
	Enforcer    *casbin.Enforcer
	CasbinTable string
}

type CasbinPolicy struct {
	Sub     string
	Obj     string
	Act     string
}

type CasbinGroupingPolicy struct {
	Member  string
	Role    string
}

type CasbinObject struct {
	Obj     string
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
func CasbinListRoles(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles := make([]string, 0)
		query := fmt.Sprintf("SELECT DISTINCT %s FROM ? WHERE %s = ?", "v1", "p_type")
		rows, err := mariadb.DataBase.QueryContext(c, query, csbn.CasbinTable, "g")
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Query Roles Error",
			})
		}
		for rows.Next() {
			var role string
			if err := rows.Scan(&role); err != nil {
				slog.ErrorContext(c, err.Error())
			}
			roles = append(roles, role)
		}
		if err := rows.Err(); err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "List Roles Error",
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status": "success",
			"roles":  roles,
		})
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
func CasbinListMembers(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		members := make([]string, 0)
		query := fmt.Sprintf("SELECT DISTINCT %s FROM %s WHERE %s = ?", "v0", csbn.CasbinTable, "p_type")
		rows, err := mariadb.DataBase.QueryContext(c, query, "g")
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Query Members Error",
			})
		}
		for rows.Next() {
			var role string
			if err := rows.Scan(&role); err != nil {
				slog.ErrorContext(c, err.Error())
			}
			members = append(members, role)
		}
		if err := rows.Err(); err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "List Members Error",
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status":  "success",
			"members": members,
		})
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
func CasbinGetRole(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Path Parameter Error",
			})
		}
		members := make([]string, 0)
		query := fmt.Sprintf(
			"SELECT DISTINCT %s FROM %s WHERE %s = ? AND %s = ?",
			"v0",
			csbn.CasbinTable,
			"p_type",
			"v1",
		)
		rows, err := mariadb.DataBase.QueryContext(c, query, "g", name)
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Query Role And Members Error",
			})
		}
		for rows.Next() {
			var account string
			if err := rows.Scan(&account); err != nil {
				slog.ErrorContext(c, err.Error())
			}
			members = append(members, account)
		}
		if err := rows.Err(); err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Get Members With This Role Error",
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status":  "success",
			"members": members,
		})
	}
}

// @Summary Get Roles with Member
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
func CasbinGetMember(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Path Parameter Error",
			})
		}
		roles := make([]string, 0)
		query := fmt.Sprintf(
			"SELECT DISTINCT %s FROM %s WHERE %s = ? AND %s = ?",
			"v1",
			csbn.CasbinTable,
			"p_type",
			"v0",
		)
		rows, err := mariadb.DataBase.QueryContext(c, query, "g", name)
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Query Role And Members Error",
			})
		}
		for rows.Next() {
			var account string
			if err := rows.Scan(&account); err != nil {
				slog.ErrorContext(c, err.Error())
			}
			roles = append(roles, account)
		}
		if err := rows.Err(); err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Get Roles Attached To This Member Error",
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status": "success",
			"roles":  roles,
		})
	}
}

// @Summary Add RBAC Policy
// @Description new a role/policy
// @Tags privilege
// @Accept multipart/form-data
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
func CasbinAddPolicy(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		if err = c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Fail to parse POST form data.",
			})
		}
		postData := &CasbinPolicy{}
		if err = c.Bind(&postData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Fail to bind POST form data.",
			})
		}
		if ok, err := csbn.Enforcer.AddPolicy(postData.Sub, postData.Obj, postData.Act); !ok {
			if err != nil {
				slog.ErrorContext(c, err.Error())
				c.JSON(http.StatusBadRequest, gin.H {
					"status":  "fail",
					"message": "Add Policy Error",
				})
			}
			c.JSON(http.StatusOK, gin.H {
				"status":  "success",
				"message": "This policy already exists.",
				"subject": postData.Sub,
				"object":  postData.Obj,
				"action":  postData.Act,
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status":  "success",
			"message": "Added policy successfully.",
			"subject": postData.Sub,
			"object":  postData.Obj,
			"action":  postData.Act,
		})
	}
}

// @Summary Add RBAC Grouping Policy
// @Description new a group (role-member) policy
// @Tags privilege
// @Accept multipart/form-data
// @Produce application/json
// @Param subject formData string false "Subject"
// @Param object formData string false "Object"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/grouping/add [post]
func CasbinAddGroupingPolicy(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		if err = c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Fail to parse POST form data.",
			})
		}
		postData := &CasbinGroupingPolicy{}
		if err = c.Bind(&postData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Fail to bind POST form data.",
			})
		}
		if ok, err := csbn.Enforcer.AddGroupingPolicy(postData.Member, postData.Role); !ok {
			if err != nil {
				slog.ErrorContext(c, err.Error())
				c.JSON(http.StatusBadRequest, gin.H {
					"status":  "fail",
					"message": "Add Grouping Policy Error",
				})
			}
			c.JSON(http.StatusOK, gin.H {
				"status":  "success",
				"message": "This policy already exists.",
				"member":  postData.Member,
				"role":    postData.Role,
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status":  "success",
			"message": "Added role-member policy successfully.",
			"member":  postData.Member,
			"role":    postData.Role,
		})
	}
}

// @Summary Delete RBAC Policy
// @Description delete a policy
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Role Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/policy/{name}/delete [post]
func CasbinDeletePolicy(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Path Parameter Error",
			})
		}
		if ok, err := csbn.Enforcer.DeleteRole(name); !ok {
			if err != nil {
				slog.ErrorContext(c, err.Error())
				c.JSON(http.StatusBadRequest, gin.H {
					"status":  "fail",
					"message": "Delete Policy Error",
				})
			}
			c.JSON(http.StatusOK, gin.H {
				"status":  "success",
				"message": "This role not exists.",
				"role":    name,
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status":  "success",
			"message": "Deleted role/policy successfully.",
			"role":    name,
		})
	}
}

// @Summary Delete RBAC Grouping Policy
// @Description delete a grouping policy
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Member Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/grouping/{name}/delete [post]
func CasbinDeleteGroupingPolicy(csbn *CasbinConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		name, err := url.QueryUnescape(c.Param("name"))
		if err != nil {
			slog.ErrorContext(c, err.Error())
			c.JSON(http.StatusBadRequest, gin.H {
				"status":  "fail",
				"message": "Path Parameter Error",
			})
		}
		if ok, err := csbn.Enforcer.DeleteUser(name); !ok {
			if err != nil {
				slog.ErrorContext(c, err.Error())
				c.JSON(http.StatusBadRequest, gin.H {
					"status":  "fail",
					"message": "Delete Grouping Policy Error",
				})
			}
			c.JSON(http.StatusOK, gin.H {
				"status":  "success",
				"message": "This member not exists.",
				"member":  name,
			})
		}
		c.JSON(http.StatusOK, gin.H {
			"status":  "success",
			"message": "Deleted member successfully.",
			"member":  name,
		})
	}
}
