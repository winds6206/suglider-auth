package session

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/encrypt"
	"suglider-auth/internal/redis"
  )


func AddSession(c *gin.Context) {

	// Genertate session ID with no Dash
	sessionID := encrypt.GenertateUUID(true)

	session := sessions.Default(c)

	session.Set("sid", sessionID)
	session.Save()

	redisKey := "sid:" + sessionID
	redisValue := `{"username": "tony"}`

	// Value can be 1h, 1m, 10s, 2days would be 48h.
	// Value 0 means no limit TTL.
	redisTTL := "0"

	redis.Set(redisKey, redisValue, redisTTL)
	c.JSON(200, gin.H{"add-sid": session.Get("sid")})
}

func ReadSession(c *gin.Context) {

	session := sessions.Default(c)

	c.JSON(200, gin.H{"read-sid": session.Get("sid")})
}