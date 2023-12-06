package redis

import (
	"context"
	"fmt"
	"log/slog"
	"suglider-auth/configs"
	"time"

	"github.com/redis/go-redis/v9"
)

var rdb *redis.Client
var ctx = context.Background()

func init() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     configs.ApplicationConfig.Redis.Host + ":" + configs.ApplicationConfig.Redis.Port,
		Password: configs.ApplicationConfig.Redis.Password,
		DB:       0, // use default DB
	})

	pong, err := rdb.Ping(ctx).Result()
	if err != nil {
		errorMessage := fmt.Sprintf("Can not connect to redis: %v", err)
		slog.Error(errorMessage)

		panic(err)
	}

	slog.Info(fmt.Sprintf("Connected to Redis successfully, redis master return: %s", pong))

}

// Redis SET
func Set(key, value string, ttl time.Duration) error {

	err := rdb.Set(ctx, key, value, ttl).Err()
	if err != nil {
		return err
	}

	return nil
}

// Redis GET
func Get(key string) (string, int64, error) {

	var errCode int64
	errCode = 0

	value, err := rdb.Get(ctx, key).Result()

	// Check whether key exist or not
	if err == redis.Nil {
		errCode = 1043
		return "", errCode, err

	} else if err != nil {
		errCode = 1044
		return "", errCode, err

	} else {
		return value, errCode, nil
	}
}

// Redis EXISTS
func Exists(key string) (bool, error) {

	isExists, err := rdb.Exists(ctx, key).Result()

	if err != nil {
		return false, err
	}

	// Check whether key exist or not
	if isExists == 1 {
		return true, nil
	} else {
		return false, nil
	}
}

// Redis DELETE
func Delete(key string) error {

	err := rdb.Del(ctx, key).Err()
	if err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("Delete key(%s) successfully.", key))

	return nil
}

// Close redis connection
func Close() {
	rdb.Close()
	return
}
