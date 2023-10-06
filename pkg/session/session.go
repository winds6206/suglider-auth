package session

import (
	"sync"
	// "fmt"
	"net/http"
	"github.com/gorilla/sessions"
	"github.com/gin-gonic/gin"
)

type SessContent struct {
	Username	string
}

var Session string
var SessListLock sync.RWMutex
var SessList = make(map[string]SessContent)


// func AddSession(sid string, sessData SessContent) {
// 	SessListLock.Lock()
// 	SessList[sid] = sessData
// 	Session = sid
// 	SessListLock.Unlock()

// 	fmt.Println(SessList)
// }

var store = sessions.NewCookieStore([]byte("suglider"))

func AddSession(c *gin.Context) {
	
	session, _ := store.Get(c.Request, "session-key")
	// session.Values["authenticated"] = true

    // Set session expire time
    session.Options = &sessions.Options{
        MaxAge:   1 * 60 * 60,  // 24hr unit second
        HttpOnly: true,
    }

	err := session.Save(c.Request, c.Writer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
}

func GetSession(c *gin.Context) {

	session, _ := store.Get(c.Request, "session-key")
	sessionID := session.ID
	c.JSON(http.StatusOK, gin.H{"session_id": sessionID})

}

// func CheckSession() bool {
// 	SessionListLock.RLock()
// 	_, ok := SessionList[UserSession]
// 	SessionListLock.RUnlock()
// 	// 如果有seesion 回傳 true
// 	if ok {
// 		return true
// 	}

// 	return false
// }