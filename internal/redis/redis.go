package redis

import (
	"github.com/redis/go-redis/v9"
	"suglider-auth/configs"
	"log"
	"context"
	"time"
)

var rdb *redis.Client
var ctx = context.Background()

func init() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     configs.ApplicationConfig.Redis.Host + ":" + configs.ApplicationConfig.Redis.Port,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	pong, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Println("Can not connect to redis:", err)
		panic(err)
	}

	log.Println("Connected to Redis successfully, redis master return:", pong)
}

// // Redis SET
// func Set(key, value , ttl string) {

// 	var (
// 		err error
// 		ttlDuration time.Duration
// 	)

//     ttlDuration, err = time.ParseDuration(ttl)
//     if err != nil {
//         log.Println("TTL string convert to duration failed:", err)
// 		return
//     }

// 	err = rdb.Set(ctx, key, value, ttlDuration).Err()
// 	if err != nil {
// 		log.Println("Redis SET data have something problem:", err)
// 		return
// 	}
// }

// Redis SET
func Set(key, value string, ttl time.Duration) {

	err := rdb.Set(ctx, key, value, ttl).Err()
	if err != nil {
		log.Println("Redis SET data have something problem:", err)
		return
	}
}


// Close redis connection
func Close() {
	rdb.Close()
	return
}
