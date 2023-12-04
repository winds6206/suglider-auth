package api_server

import (
	"log/slog"
	"net/http"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/jwt"
	"suglider-auth/pkg/rbac"
	"suglider-auth/pkg/session"
	"time"

	"github.com/gin-gonic/gin"
)

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
	"/api/v1/user/forgot-password",
	"/api/v1/user/verify-mail",
	"/api/v1/user/verify-mail/resend",
	"/api/v1/totp/validate",
	"/api/v1/otp/mail-verify",
	"/api/v1/otp/mail-send",
	"/api/v1/oauth/google/login",
	"/api/v1/oauth/google/callback",
	"/api/v1/totp/generate",
	"/api/v1/totp/verify",
	"/api/v1/totp/validate",
	"/api/v1/totp/disable",
}

func checkAPIWhileList(c *gin.Context) bool {
	urlPath := c.Request.URL.Path
	for _, listPath := range apiWhileList {
		if listPath == urlPath {
			return true
		}
	}
	return false
}

func checkSessionID(c *gin.Context) bool {
	isExists, _ := session.CheckSession(c)

	if isExists {
		return true
	} else {
		return false
	}
}

func CheckUserJWT() gin.HandlerFunc {

	return func(c *gin.Context) {

		if checkAPIWhileList(c) {
			c.Next()
			return
		}

		cookie, err := c.Cookie("token")

		if err != nil {
			if err == http.ErrNoCookie {
				isExists := checkSessionID(c)
				if isExists {
					c.Next()
					return
				} else {
					c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1019, map[string]interface{}{
						"msg": "Both of JWT and sessionID can't found.",
					}))
					return
				}
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
