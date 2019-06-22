package goworker

import (
	"time"

	"gopkg.in/redis.v5"
)

func newRedisClient(redisUrl string, poolSize int) (*redis.Client, error) {
	option, err := redis.ParseURL(redisUrl)
	if err != nil {
		return nil, err
	}
	option.PoolSize = poolSize
	option.ReadTimeout = time.Second * 30
	option.WriteTimeout = time.Second * 30
	return redis.NewClient(option), nil
}
