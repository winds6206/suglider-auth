package session

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/encrypt"
	"suglider-auth/internal/redis"
	"encoding/json"
	"net/http"
	"log"
	"suglider-auth/pkg/time_convert"
  )

type sessionData struct {
	Username	string	`json:"username"`
}

func AddSession(user string, c *gin.Context) {

	sessionValue := sessionData{
		Username: user,
	}

	jsonSessionValue, err := json.Marshal(sessionValue)
	if err != nil {
		log.Println("Failed to create session value JSON data:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session value JSON data"})
		return
	}

	// Genertate session ID with no Dash
	sessionID := encrypt.GenertateUUID(true)

	session := sessions.Default(c)

	session.Set("sid", sessionID)
	session.Save()

	redisKey := "sid:" + sessionID
	redisValue := string(jsonSessionValue)

	log.Println(redisValue)

	// Value can be 1h, 1m, 10s, 2days would be 48h.
	// Value 0 means no limit TTL.
	// redisTTL := "0"

	// time_convert.RedisTTL is a global variable from time_convert.go
	redis.Set(redisKey, redisValue, time_convert.RedisTTL)
	c.JSON(200, gin.H{"add-sid": session.Get("sid")})
}

func ReadSession(c *gin.Context) {

	session := sessions.Default(c)

	c.JSON(200, gin.H{"read-sid": session.Get("sid")})
}