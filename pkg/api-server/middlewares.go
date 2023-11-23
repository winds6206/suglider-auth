package api_server

import (
	"fmt"
	"log/slog"
	"net/http"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/jwt"
	"suglider-auth/pkg/rbac"
	"time"

	"github.com/gin-gonic/gin"
)

func AuthenticationMiddleware(mode int) gin.HandlerFunc {
	return func(c *gin.Context) {
		switch mode {
		case 1:

			// TODO

		case 2:

			// TODO

		case 3:

			// TODO

		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid authentication mode"})
			c.Abort()
			return
		}
	}
}

func userPrivilege(csbn *rbac.CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub, exist := c.Get("Username")
		if !exist {
			sub = "anonymous"
		}
		obj := c.Request.URL.Path // c.Request.URL.RequestURI()
		act := c.Request.Method

		switch c.Request.URL.Path {
		case "/login", "/sing-up", "/api/v1/user/login",
			"/api/v1/user/logout", "/api/v1/user/sing-up":
			sub = "anonymous"
		default:
		}

		if pass, err := csbn.Enforcer.Enforce(sub.(string), obj, act); !pass {
			if err != nil {
				slog.ErrorContext(c, err.Error())
			}
			c.Redirect(http.StatusTemporaryRedirect, "/login")
			c.Abort()
			// c.AbortWithStatusJSON(http.StatusForbidden, gin.H {
			// 	"status": "forbidden",
			// 	"message": "You don't have the required permission.",
			// })
		}
		c.Next()
	}
}

var apiWhileList = []string{
	"/api/v1/user/sign-up",
	"/api/v1/user/login",
}

func CheckUserJWT() gin.HandlerFunc {

	return func(c *gin.Context) {

		urlPath := c.Request.URL.Path
		for _, listPath := range apiWhileList {
			if listPath == urlPath {
				c.Next()
				return
			}
		}

		cookie, err := c.Cookie("token")

		if err != nil {
			if err == http.ErrNoCookie {
				fmt.Println("123456")
				c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1019, err))
				return
			}
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1020, err))
			return
		}

		claims, errCode, errParseJWT := jwt.ParseJWT(cookie)

		if errParseJWT != nil {

			switch errCode {

			case 1015:
				c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, errCode, err))
				return

			case 1016:
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, errCode, err))
				return

			case 1017:
				c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, errCode, err))
				return
			}
		}

		if time.Now().Unix() > claims.ExpiresAt.Unix() {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1050, err))
			return
		} else {
			c.Next()
		}
	}
}
