package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"zeroScannerGo/engine"
	"github.com/benmanns/goworker"
)

func init() {
	s := defaultWorkerSettings()
	s.URI = "redis://192.168.206.129:6379/0"
	s.Queues.Set("taskQueue")
	goworker.SetSettings(s)
}

func defaultWorkerSettings() goworker.WorkerSettings {
	return goworker.WorkerSettings{
		Concurrency:    3,
		Connections:    20,
		UseNumber:      true,
		ExitOnComplete: false,
		Interval:       5.0,
	}
}

func pushTask(params string) error {
	return goworker.Enqueue(&goworker.Job{
		Queue: "taskQueue",
		Payload: goworker.Payload{
			Class: "scan",
			Args:  []interface{}{"test_task_001", "zabbix_sqlinject", params},
		},
	})
}

func main() {
	target := "https://www.jd.com"
	parsedTarget, err := url.Parse(target)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	params := engine.Params{
		Method:       "GET",
		Target:       target,
		ParsedTarget: *parsedTarget,
		Cookie:       "pin=waimianyougesongshu",
	}

	paramsByte, _ := json.Marshal(params)
	for {
		err := pushTask(string(paramsByte))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("added")
		time.Sleep(100 * time.Millisecond)
	}

}
