package main

import (
	"encoding/json"

	"zeroScannerGo/engine"
	"zeroScannerGo/lib/goworker"
)

func sendResult(scanResult engine.Result) error {
	data, _ := json.Marshal(scanResult)
	for {
		err := goworker.Enqueue(&goworker.Job{
			Queue: "resultQueue",
			Payload: goworker.Payload{
				Class: "saveScanResult",
				Args:  []interface{}{string(data)},
			},
		})
		if err != nil {
			agent.Logger.Error(err)
			continue
		}
		return nil
	}
}

func sendRegist(agentId, token, queues string, workerNum int) error {
	return goworker.Enqueue(&goworker.Job{
		Queue: "registQueue",
		Payload: goworker.Payload{
			Class: "register",
			Args:  []interface{}{agentId, token, queues, workerNum},
		},
	})
}
