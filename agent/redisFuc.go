package main

import (
	"fmt"
	"time"
)

func syncAgentInfoToRedis() error {
	pipe := agent.redisClient.Pipeline()
	pipe.Set(fmt.Sprintf("freeworker:%s", agent.Id), agent.FreeWorker(), time.Second*3)
	pipe.Set(fmt.Sprintf("totalworker:%s", agent.Id), agent.conf.workerSettings.Concurrency, time.Second*3)
	pipe.SAdd("agents", agent.Id)
	_, err := pipe.Exec()
	pipe.Close()
	return err
}
