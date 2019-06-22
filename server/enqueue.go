package main

import (
	"encoding/json"

	"zeroScannerGo/engine"
	"zeroScannerGo/lib/goworker"
)

func PushTask(queue, taskId, taskType, pocName string, params engine.Params) error {
	data, _ := json.Marshal(params)
	for {
		err := goworker.Enqueue(&goworker.Job{
			Queue: queue,
			Payload: goworker.Payload{
				Class: "scan",
				Args:  []interface{}{taskId, taskType, pocName, string(data)},
			},
		})
		if err != nil {
			server.Logger.Error(err)
			continue
		}
		return nil
	}
}

func SyncCookie(queue string, cookieMap map[string]string) error {
	return goworker.Enqueue(&goworker.Job{
		Queue: queue,
		Payload: goworker.Payload{
			Class: "sync",
			Args:  []interface{}{"cookie", cookieMap},
		},
	})
}

func SyncSource(queue string, sourceMap map[string]string) error {
	return goworker.Enqueue(&goworker.Job{
		Queue: queue,
		Payload: goworker.Payload{
			Class: "sync",
			Args:  []interface{}{"source", sourceMap},
		},
	})
}

func SyncPoc(queue string, pocMap map[string]engine.Poc) error {
	return goworker.Enqueue(&goworker.Job{
		Queue: queue,
		Payload: goworker.Payload{
			Class: "sync",
			Args:  []interface{}{"poc", pocMap},
		},
	})
}

func Reload(queue string) error {
	return goworker.Enqueue(&goworker.Job{
		Queue: queue,
		Payload: goworker.Payload{
			Class: "sync",
			Args:  []interface{}{"reload"},
		},
	})
}

func ReloadAllAgent() error {
	agentIds, err := getAgentList()
	if err != nil {
		server.Logger.Error(err)
		return err
	}
	for _, agentId := range agentIds {
		queue := agentId + "_sync"
		err := Reload(queue)
		if err != nil {
			server.Logger.Error(err)
			return err
		}
	}
	return nil
}

func SyncToAgent(cookieMap, sourceMap map[string]string, pocMap map[string]engine.Poc) error {
	agentIds, err := getAgentList()
	if err != nil {
		server.Logger.Error(err)
		return err
	}

	for _, agentId := range agentIds {
		queue := agentId + "_sync"
		if cookieMap != nil {
			err := SyncCookie(queue, cookieMap)
			if err != nil {
				server.Logger.Error(err)
				return err
			}
		}
		if sourceMap != nil {
			err := SyncSource(queue, sourceMap)
			if err != nil {
				server.Logger.Error(err)
				return err
			}
		}
		if pocMap != nil {
			err := SyncPoc(queue, pocMap)
			if err != nil {
				server.Logger.Error(err)
				return err
			}
		}
	}
	return nil
}
