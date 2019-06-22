package main

import (
	"gopkg.in/redis.v5"
)

func newRedisClient(redisUrl string, db int, poolSize int) (*redis.Client, error) {
	option, err := redis.ParseURL(redisUrl)
	if err != nil {
		return nil, err
	}
	option.DB = db
	option.PoolSize = poolSize
	return redis.NewClient(option), nil
}
