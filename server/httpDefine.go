package main

import (
	"zeroScannerGo/engine"
)

type PocTestS struct {
	Poc    engine.Poc    `json:"poc"`
	Params engine.Params `json:"params"`
}

type PluginTask struct {
	Target     []string          //目标列表，跟流量数据一样的格式
	Cookie     string            //任务使用的自定义cookie
	Hosts      map[string]string //任务使用hosts
	FilterHost []string          `json:"filter_host"` //任务中所有涉及到的域名及ip
}
