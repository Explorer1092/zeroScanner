package main

import (
	"strconv"
	"strings"
)

/*
map[string]int{
	"agentid":"totalworker",
}
map[string]int{
	"agentid":"freeworker",
}
*/
func getAgentWorkerMap() (map[string]int, map[string]int, error) {
	var (
		agentTotalWorkerMap = map[string]int{}
		agentFreeWorkerMap  = map[string]int{}
		deadAgents          []interface{}
	)
	agentList, err := server.redisClient.SMembers("agents").Result()
	if err != nil {
		return nil, nil, err
	}

	l := len(agentList)
	if l == 0 {
		return agentTotalWorkerMap, agentFreeWorkerMap, nil
	}

	queryList := make([]string, l*2)
	for index, agentId := range agentList {
		queryList[index] = "totalworker:" + agentId
		queryList[index+l] = "freeworker:" + agentId
	}

	reply, err := server.redisClient.MGet(queryList...).Result()
	if err != nil {
		return nil, nil, err
	}

	for index, agentId := range agentList {
		if reply[index] != nil && reply[index+l] != nil {
			totalWorker, _ := strconv.Atoi(reply[index].(string))
			freeWorker, _ := strconv.Atoi(reply[index+l].(string))
			agentTotalWorkerMap[agentId] = totalWorker
			agentFreeWorkerMap[agentId] = freeWorker
		} else {
			deadAgents = append(deadAgents, agentList[index])
		}
	}

	delDeadAgent("agents", deadAgents)

	return agentTotalWorkerMap, agentFreeWorkerMap, nil
}

//[]string{agentlist}
func getAgentList() ([]string, error) {
	var agentList []string
	agentTotalWorkerMap, _, err := getAgentWorkerMap()
	if err != nil {
		return nil, err
	}

	for agentId, _ := range agentTotalWorkerMap {
		agentList = append(agentList, agentId)
	}
	return agentList, nil
}

/*
map[string]int{
	"schedulerName":10,
}
map[string]int{
	"schedulerName":10,
}
*/
func getSchedulerWorkerMap() (map[string]int, map[string]int, error) {
	var (
		schedulerTotalWorkerMap = map[string]int{}
		schedulerFreeWorkerMap  = map[string]int{}
	)
	agentTotalWorkerMap, agentFreeWorkerMap, err := getAgentWorkerMap()
	if err != nil {
		return nil, nil, err
	}

	for agentId, totalWorker := range agentTotalWorkerMap {
		schedulerName := strings.SplitN(agentId, ":", 2)[0]
		schedulerTotalWorkerMap[schedulerName] += totalWorker
		schedulerFreeWorkerMap[schedulerName] += agentFreeWorkerMap[agentId]
	}

	return schedulerTotalWorkerMap, schedulerFreeWorkerMap, nil
}

/*
totalworker, freeworker, error
*/
func getSchedulerWorker(schedulerName string) (int, int, error) {
	schedulerTotalWorkerMap, schedulerFreeWorkerMap, err := getSchedulerWorkerMap()
	if err != nil {
		return 0, 0, err
	}
	return schedulerTotalWorkerMap[schedulerName], schedulerFreeWorkerMap[schedulerName], nil
}

func delDeadAgent(key string, agentIds []interface{}) error {
	if len(agentIds) > 0 {
		return server.redisClient.SRem(key, agentIds...).Err()
	}
	return nil
}

func syncRegistInfo(agentId string) error {
	syncQueue := agentId + "_sync"
	err := SyncCookie(syncQueue, server.cookieHandler.Cookies())
	if err != nil {
		return err
	}

	sourceMap, err := loadSourceMap()
	if err != nil {
		return err
	}
	err = SyncSource(syncQueue, sourceMap)
	if err != nil {
		return err
	}

	pocMap, err := loadPoc(nil)
	if err != nil {
		return err
	}
	err = SyncPoc(syncQueue, pocMap)
	if err != nil {
		return err
	}

	server.Logger.Info("syncRegistInfo sended, queue:", syncQueue)
	return nil
}
