// 研发自测扫描任务调度
package main

import (
	"zeroScannerGo/engine/lib/set"
)

func newTechPublicSchedulerArgs() *SchedulerArgs {
	s := &SchedulerArgs{
		Name:  "techPublic",
		Queue: "techPublicQueue",
		KeyList: []string{
			"techAdd", //研发手动添加的外网任务
		},
	}
	s.GetNewTaskFunc = techGetNewTask
	//	s.HandleTaskItemListFunc = s.handleTaskItemList
	s.DisabledPocs = set.New()
	disabledPocs, err := getDisabledPocs(s.Name)
	if err != nil {
		server.Logger.Error(err)
	} else {
		for _, pocName := range disabledPocs {
			s.DisabledPocs.Add(pocName)
		}
	}
	return s
}

func newTechPrivateSchedulerArgs() *SchedulerArgs {
	s := &SchedulerArgs{
		Name:  "techPrivate",
		Queue: "techPrivateQueue",
		KeyList: []string{
			"techAdd", //研发手动添加的内网任务
		},
	}
	s.GetNewTaskFunc = techGetNewTask
	//	s.HandleTaskItemListFunc = s.handleTaskItemList
	s.DisabledPocs = set.New()
	disabledPocs, err := getDisabledPocs(s.Name)
	if err != nil {
		server.Logger.Error(err)
	} else {
		for _, pocName := range disabledPocs {
			s.DisabledPocs.Add(pocName)
		}
	}
	return s
}

func techGetNewTask(s *SchedulerArgs, key string) (*Task, error) {
	err := handleSpiderTask(s)
	if err != nil {
		server.Logger.Error(err)
	}
	return defaultGetNewTask(s, key)
}
