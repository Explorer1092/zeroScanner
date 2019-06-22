package main

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"zeroScannerGo/engine"
)

func scanWorker(queue string, args ...interface{}) error {
	atomic.AddInt64(&agent.freeWorkerCount, -1)
	defer atomic.AddInt64(&agent.freeWorkerCount, 1)

	var (
		taskId   = args[0].(string)
		taskType = args[1].(string)
		pocName  = args[2].(string)
		params   = engine.Params{}
		result   engine.Result
	)

	//	agent.Logger.Debug(taskId, taskType, pocName, args[3].(string))
	//	defer agent.Logger.Debug(taskId, "finished")

	err := json.Unmarshal([]byte(args[3].(string)), &params)
	if err != nil {
		result = engine.Result{}
		result.Err = err.Error()
	} else {
		// 防止agent还未同步完poc就开始扫描
		for !agent.registered {
			time.Sleep(time.Second)
		}

		startTime := time.Now()

		result = agent.engine.RunPoc(pocName, params)

		timeCost := time.Now().Sub(startTime)
		if timeCost > time.Minute*15 {
			agent.Logger.Warn(pocName, "took", timeCost, params.ParsedTarget.String(), params.Data)
		}
	}

	result.TaskId = taskId
	result.TaskType = taskType

	return sendResult(result)
}

func syncWorker(queue string, args ...interface{}) error {
	t := args[0].(string)
	var err error
	switch t {
	case "cookie":
		err = handleCookieUpdate(args[1].(map[string]interface{}))
	case "poc":
		err = handlePocUpdate(args[1].(map[string]interface{}))
	case "source":
		err = handleSourceUpdate(args[1].(map[string]interface{}))
	case "reload":
		err = handleReload()
	}

	if err != nil {
		agent.Logger.Error(err)
	}
	return err
}
