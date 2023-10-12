package time_convert

import (
	"time"
	"log"
)

var CookieMaxAge int
var RedisTTL time.Duration

func ConvertTimeFormat(ttl string) {

	var (
		err error
		ttlDuration time.Duration
	)

    ttlDuration, err = time.ParseDuration(ttl)
    if err != nil {
        log.Println("TTL string convert to duration failed:", err)
		panic(err)
    }

	CookieMaxAge = int(ttlDuration.Seconds())
	RedisTTL = ttlDuration
    // return cookieMaxAge, redisTTL
}