package api_server

import (
	"fmt"
	"log/slog"
	"net/http"
	"suglider-auth/internal/utils"
	"suglider-auth/pkg/jwt"
	"suglider-auth/pkg/rbac"
	"suglider-auth/pkg/session"
	"time"

	"github.com/gin-gonic/gin"
)

// The Casbin middleware does not immediately update the database.
func userPrivilege(csbn *rbac.CasbinEnforcerConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		sub, exist := c.Get("mail")

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

		fmt.Println(sub)
		fmt.Println(obj)
		fmt.Println(act)

		pass, err := csbn.Enforcer.Enforce(sub.(string), obj, act)
		fmt.Println(pass)
		if err != nil {
			errorMessage := fmt.Sprintf("Check user permission failed: %v", err)
			slog.Error(errorMessage)
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1065, err))
			c.Abort()
			return
		}
		if !pass {
			c.JSON(http.StatusForbidden, utils.ErrorResponse(c, 1064, nil))
			c.Abort()
			return
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
	"/api/v1/otp/mail/verify",
	"/api/v1/otp/mail/send",
	"/api/v1/oauth/google/login",
	"/api/v1/oauth/google/sign-up",
	"/api/v1/oauth/google/callback",
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
					_, data, errCode, err := session.ReadSession(c)

					switch errCode {
					case 1043:
						errorMessage := fmt.Sprintf("Redis key does not exist: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
						c.Abort()
						return

					case 1044:
						errorMessage := fmt.Sprintf("Redis GET data failed: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
						c.Abort()
						return

					case 1063:
						errorMessage := fmt.Sprintf("The json data unmarshal failed: %v", err)
						slog.Error(errorMessage)
						c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, errCode, err))
						c.Abort()
						return
					}

					c.Set("mail", data.Mail)
					c.Next()
					return
				} else {
					c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1019, map[string]interface{}{
						"msg": "Both of JWT and sessionID can't found.",
					}))
					c.Abort()
					return
				}
			}
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(c, 1020, err))
			c.Abort()
			return
		}

		// Get client JWT
		claims, errCode, errParseJWT := jwt.ParseJWT(cookie)

		if errParseJWT != nil {

			switch errCode {

			case 1015:
				c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, errCode, err))
				c.Abort()
				return

			case 1016:
				c.JSON(http.StatusBadRequest, utils.ErrorResponse(c, errCode, err))
				c.Abort()
				return

			case 1017:
				c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, errCode, err))
				c.Abort()
				return
			}
		}

		if time.Now().Unix() > claims.ExpiresAt.Unix() {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(c, 1050, err))
			return
		} else {
			c.Set("mail", claims.Mail)
			c.Next()
		}
	}
}
