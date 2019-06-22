package goworker

import (
	"encoding/json"
	"fmt"
)

var (
	workers map[string]workerFunc
)

func init() {
	workers = make(map[string]workerFunc)
}

// Register registers a goworker worker function. Class
// refers to the Ruby name of the class which enqueues the
// job. Worker is a function which accepts a queue and an
// arbitrary array of interfaces as arguments.
func Register(class string, worker workerFunc) {
	workers[class] = worker
}

func Enqueue(job *Job) error {
	err := Init()
	if err != nil {
		return err
	}

	buffer, err := json.Marshal(job.Payload)
	if err != nil {
		logger.Error("Cant marshal payload on enqueue")
		return err
	}

	err = redisClient.RPush(fmt.Sprintf("%squeue:%s", workerSettings.Namespace, job.Queue), buffer).Err()
	if err != nil {
		logger.Error("Cant push to queue")
		return err
	}

	return nil
}
