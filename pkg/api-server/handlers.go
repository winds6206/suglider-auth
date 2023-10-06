package api_server

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"net/url"
	mariadb "suglider-auth/internal/database/connect"
)

// @Summary Show Information (Simple Health Check)
// @Description show the fundamental informations of this server
// @Tags general
// @Accept application/json
// @Produce application/json
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /healthz [get]
func (aa *AuthApiSettings) healthzHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, gin.H {
		"Name":            aa.Name,
		"Version":         aa.Version,
		"X-FORWARDED-FOR": c.Request.Header.Get("X-Forwarded-For"),
	})
}

type CasbinPolicy struct {
	Sub  string
	Obj  string
	Act  string
}

type CasbinRole struct {
	Role   string
	Member string
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
func (aa *AuthApiSettings) CasbinListRoles(c *gin.Context) {
	roles := make([]string, 0)
	query := fmt.Sprintf("SELECT DISTINCT %s FROM ? WHERE %s = ?", "v1", "p_type")
	rows, err := mariadb.DataBase.QueryContext(c, query, aa.CasbinTable, "g")
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
func (aa *AuthApiSettings) CasbinListMembers(c *gin.Context) {
	members := make([]string, 0)
	query := fmt.Sprintf("SELECT DISTINCT %s FROM %s WHERE %s = ?", "v0", aa.CasbinTable, "p_type")
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
func (aa *AuthApiSettings) CasbinGetRole(c *gin.Context) {
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
		aa.CasbinTable,
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
func (aa *AuthApiSettings) CasbinGetMember(c *gin.Context) {
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
		aa.CasbinTable,
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

type rbacRolePostForm struct {
	sub string
	obj string
	act string
}

// @Summary Add RBAC Role/Policy
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
// @Router /api/v1/rbac/role/add [post]
func (aa *AuthApiSettings) CasbinAddRole(c *gin.Context) {
	var err error
	if err = c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Fail to parse POST form data.",
		})
	}
	postData := &rbacRolePostForm{}
	if err = c.Bind(&postData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Fail to bind POST form data.",
		})
	}
	stmt := fmt.Sprintf("INSERT IGNORE INTO %s (p_type, v0, v1, v2) VALUES (?, ?, ?, ?)", aa.CasbinTable)
	if _, err = mariadb.DataBase.ExecContext(c, stmt, "p", postData.sub, postData.obj, postData.act);
	err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Add Role Error",
		})
	}
	c.JSON(http.StatusOK, gin.H {
		"status":  "success",
		"message": "Added role/policy successfully.",
		"subject": postData.sub,
		"object":  postData.obj,
		"action":  postData.act,
	})
}

type rbacObjectPostForm struct {
	sub string
	obj string
}

// @Summary Add RBAC Role-Member Policy
// @Description new a role-member policy
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
// @Router /api/v1/rbac/member/add [post]
func (aa *AuthApiSettings) CasbinAttachRoleToMember(c *gin.Context) {
	var err error
	if err = c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Fail to parse POST form data.",
		})
	}
	postData := &rbacObjectPostForm{}
	if err = c.Bind(&postData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Fail to bind POST form data.",
		})
	}
	stmt := fmt.Sprintf("INSERT IGNORE INTO %s (p_type, v0, v1) VALUES (?, ?, ?)", aa.CasbinTable)
	if _, err = mariadb.DataBase.ExecContext(c, stmt, "g", postData.sub, postData.obj);
	err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Add Role Error",
		})
	}
	c.JSON(http.StatusOK, gin.H {
		"status":  "success",
		"message": "Added role-member policy successfully.",
		"subject": postData.sub,
		"object":  postData.obj,
	})
}

// @Summary Delete RBAC Role
// @Description delete a role
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Role Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/role/{name}/delete [post]
func (aa *AuthApiSettings) CasbinDeleteRole(c *gin.Context) {
	name, err := url.QueryUnescape(c.Param("name"))
	if err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Path Parameter Error",
		})
	}

	stmt := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ? AND %s = ?;",
		aa.CasbinTable,
		"p_type",
		"v0",
	)
	if _, err = mariadb.DataBase.ExecContext(c, stmt, "p", name); err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Delete Role Error",
		})
	}

	stmt = fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ? AND %s = ?;",
		aa.CasbinTable,
		"p_type",
		"v1",
	)
	if _, err = mariadb.DataBase.ExecContext(c, stmt, "g", name); err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Delete Role Error",
		})
	}
	c.JSON(http.StatusOK, gin.H {
		"status":  "success",
		"message": "Deleted role/policy successfully.",
		"member":  name,
	})
}

// @Summary Delete RBAC Member
// @Description delete a member
// @Tags privilege
// @Accept application/json
// @Produce application/json
// @Param name path string true "Member Name"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/member/{name}/delete [post]
func (aa *AuthApiSettings) CasbinDeleteMember(c *gin.Context) {
	name, err := url.QueryUnescape(c.Param("name"))
	if err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Path Parameter Error",
		})
	}

	stmt := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ? AND %s = ?;",
		aa.CasbinTable,
		"p_type",
		"v0",
	)
	if _, err = mariadb.DataBase.ExecContext(c, stmt, "p", name); err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Delete Member Error",
		})
	}

	stmt = fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ? AND %s = ?;",
		aa.CasbinTable,
		"p_type",
		"v0",
	)
	if _, err = mariadb.DataBase.ExecContext(c, stmt, "g", name); err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Delete Member Error",
		})
	}
	c.JSON(http.StatusOK, gin.H {
		"status":  "success",
		"message": "Deleted member successfully.",
		"member":  name,
	})
}

type deleteObjectPostForm struct {
	obj string
}

// @Summary Delete RBAC Object
// @Description delete a rbac object
// @Tags privilege
// @Accept multipart/form-data
// @Produce application/json
// @Param object formData string false "Object"
// @Success 200 {string} string "Success"
// @Failure 400 {string} string "Bad request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 403 {string} string "Forbidden"
// @Failure 404 {string} string "Not found"
// @Router /api/v1/rbac/object/delete [post]
func (aa *AuthApiSettings) CasbinDeleteObject(c *gin.Context) {
	var err error
	if err = c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Fail to parse POST form data.",
		})
	}
	postData := &deleteObjectPostForm{}
	if err = c.Bind(&postData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Fail to bind POST form data.",
		})
	}

	stmt := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = ? AND %s = ?;",
		aa.CasbinTable,
		"p_type",
		"v1",
	)
	if _, err = mariadb.DataBase.ExecContext(c, stmt, "p", postData.obj); err != nil {
		slog.ErrorContext(c, err.Error())
		c.JSON(http.StatusBadRequest, gin.H {
			"status":  "fail",
			"message": "Delete Object Error",
		})
	}
	c.JSON(http.StatusOK, gin.H {
		"status":  "success",
		"message": "Deleted object successfully.",
		"object":  postData.obj,
	})
}
