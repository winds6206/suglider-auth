package session

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"suglider-auth/pkg/encrypt"
	"suglider-auth/internal/redis"
	"encoding/json"
	"log/slog"
	"suglider-auth/pkg/time_convert"
	"suglider-auth/configs"
	"fmt"
  )

type sessionData struct {
	Username	string	`json:"username"`
}

func AddSession(c *gin.Context, user string) (string, int64, error) {

	var errCode int64
	errCode = 0

	sessionValue := sessionData{
		Username: user,
	}

	jsonSessionValue, err := json.Marshal(sessionValue)
	if err != nil {
		errCode = 1041
		return "", errCode, err
	}

	// Genertate session ID with no Dash
	sessionID := encrypt.GenertateUUID(true)

	session := sessions.Default(c)

	session.Set("sid", sessionID)
	session.Save()

	redisKey := "sid:" + sessionID
	redisValue := string(jsonSessionValue)

	redisTTL, _, _ := time_convert.ConvertTimeFormat(configs.ApplicationConfig.Session.Timeout)
	err = redis.Set(redisKey, redisValue, redisTTL)
	if err != nil {
		errCode = 1042
		return "", errCode, err
	}
	
	return sessionID, errCode, nil
}

func CheckSession(c *gin.Context) (bool, error) {
	session := sessions.Default(c)
	sid := session.Get("sid")

	// Process key format
	sessionKey := fmt.Sprintf("sid:%s", sid)
	
	// Exists() function will return bool
	isExists, err := redis.Exists(sessionKey)
	if err != nil {
		errorMessage := fmt.Sprintf("Checking whether key exist or not happen something wrong: %v", err)
		slog.Error(errorMessage)
		return false, err
	}

	return isExists, nil
}

func DeleteSession(sid string) error {
	// Process key format
	sessionKey := fmt.Sprintf("sid:%s", sid)
	err := redis.Delete(sessionKey)
	if err != nil {
		return err
	}

	return nil
}

func ReadSession(c *gin.Context) string {
	session := sessions.Default(c)
	sid := session.Get("sid")

	// Convert interface{} type to String type
	StrSid := fmt.Sprintf("%v", sid)
	return StrSid
}