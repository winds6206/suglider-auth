package session

import (
	"encoding/json"
	"fmt"
	"suglider-auth/configs"
	"suglider-auth/internal/redis"
	"suglider-auth/pkg/encrypt"
	"suglider-auth/pkg/time_convert"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type sessionData struct {
	Mail string `json:"mail"`
}

func AddSession(c *gin.Context, mail string) (string, int64, error) {

	var errCode int64
	errCode = 0

	sessionValue := sessionData{
		Mail: mail,
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

func ReadSession(c *gin.Context) (string, sessionData, int64, error) {

	var errCode int64
	errCode = 0

	var data sessionData

	session := sessions.Default(c)
	sid := session.Get("sid")

	// Convert interface{} type to String type
	strSid := fmt.Sprintf("%v", sid)

	// Process key format
	sessionKey := fmt.Sprintf("sid:%s", sid)

	// Get value
	value, errCode, err := redis.Get(sessionKey)
	if err != nil {
		return "", sessionData{}, errCode, err
	}

	err = json.Unmarshal([]byte(value), &data)
	if err != nil {
		errCode = 1063
		return "", sessionData{}, errCode, err
	}

	return strSid, data, errCode, nil

}
