package main

import (
	"strconv"

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

// 从redis查询队列数量
func getQueueCount(queue string) (int, error) {
	count, err := server.redisClient.LLen("queue:" + queue).Result()
	if err != nil {
		return 0, err
	}
	return int(count), err
}

func getDisabledPocs(schedulerName string) ([]string, error) {
	return server.redisClient.SMembers("disabledPocs:" + schedulerName).Result()
}

func setDisabledPocs(schedulerName string, mode int, pocNames ...interface{}) error {
	if len(pocNames) > 0 {
		if mode == 0 {
			return server.redisClient.SAdd("disabledPocs:"+schedulerName, pocNames...).Err()
		} else {
			return server.redisClient.SRem("disabledPocs:"+schedulerName, pocNames...).Err()
		}
	}
	return nil
}

func getScrollId() (string, error) {
	scrollId, err := server.redisClient.Get("scrollId").Result()
	if err != nil && err != redis.Nil {
		return "", err
	}
	return scrollId, nil
}

func saveScrollId(scrollId string) error {
	return server.redisClient.Set("scrollId", scrollId, 0).Err()
}

func getEsPage() (int, error) {
	esPage, err := server.redisClient.Get("esPage").Int64()
	if err != nil && err != redis.Nil {
		return 0, err
	}
	return int(esPage), nil
}

func saveEsPage(esPage int) error {
	return server.redisClient.Set("esPage", esPage, 0).Err()
}

func incrEsPage() error {
	return server.redisClient.Incr("esPage").Err()
}

func setScanMax(hostName string, n int) error {
	return server.redisClient.HSet("scanMax", hostName, n).Err()
}

func getScanMax() (map[string]int, error) {
	scanMaxMap := map[string]int{}
	r, err := server.redisClient.HGetAll("scanMax").Result()
	if err != nil && err != redis.Nil {
		return nil, err
	}
	for k, v := range r {
		scanMaxMap[k], _ = strconv.Atoi(v)
	}
	return scanMaxMap, nil
}

func delScanMax(hostNames ...string) error {
	return server.redisClient.HDel("scanMax", hostNames...).Err()
}

func setHostScrollId(hostName, scrollId string) error {
	return server.redisClient.HSet("hostScollId", hostName, scrollId).Err()
}

func delHostScrollId(hostNames ...string) error {
	return server.redisClient.HDel("hostScollId", hostNames...).Err()
}

func getHostScrollId() (map[string]string, error) {
	return server.redisClient.HGetAll("hostScollId").Result()
}

func setHostRoundCount(hostName string, count int) error {
	return server.redisClient.HSet("hostRollCount", hostName, count).Err()
}

func delHostRollCount(hostNames ...string) error {
	return server.redisClient.HDel("hostRollCount", hostNames...).Err()
}
