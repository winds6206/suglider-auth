package time_convert

import (
	"time"
)

func ConvertTimeFormat(ttl string) (time.Duration, int, error) {

	var (
		err error
		ttlDuration time.Duration
	)

	ttlDuration, err = time.ParseDuration(ttl)
	if err != nil {
		return 0, 0, err
	}

	convertSecond := int(ttlDuration.Seconds())

	return ttlDuration, convertSecond, nil
}