package api_server

import (
	"log/slog"
	"net/http"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

func userPrivilege(csbn *casbin.CachedEnforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub := c.GetHeader("User-Name")
		obj := c.Request.URL.Path  // c.Request.URL.RequestURI()
		act := c.Request.Method

		if c.Request.URL.Path == "/login" || c.Request.URL.Path == "/logout" {
			sub = "anonymous"
		}

		if pass, err := csbn.Enforce(sub, obj, act); !pass {
			if err != nil {
				slog.ErrorContext(c, err.Error())
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H {
				"status": "forbidden",
				"message": "You don't have the required permission.",
			})
		}
		c.Next()
	}
}
