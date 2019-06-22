package main

import (
	"sync"
)

type ScanCount struct {
	countMap  map[string]map[string]int //正在扫描计数 map[host]map[taskid]count
	countLock sync.RWMutex
	maxMap    map[string]int //域名最大扫描数量 map[host]count
	maxLock   sync.RWMutex
	totalMap  map[string]map[string]int //内存中共有多少待扫描计数 map[host]map[taskid]count
	totalLock sync.RWMutex
}

func NewScanCount() *ScanCount {
	return &ScanCount{
		countMap: map[string]map[string]int{},
		maxMap:   map[string]int{},
		totalMap: map[string]map[string]int{},
	}
}

func (sc *ScanCount) GetHostCount(hostName string) int {
	sc.countLock.RLock()
	count := 0
	for _, c := range sc.countMap[hostName] {
		count += c
	}
	sc.countLock.RUnlock()
	return count
}

func (sc *ScanCount) AddHostCount(hostName, taskId string, n int) {
	sc.countLock.Lock()
	count, ok := sc.countMap[hostName]
	if !ok {
		if n > 0 {
			sc.countMap[hostName] = map[string]int{taskId: n}
		}
		sc.countLock.Unlock()
		return
	}
	count[taskId] += n
	if count[taskId] <= 0 {
		delete(count, taskId)
	}
	if len(count) == 0 {
		delete(sc.countMap, hostName)
	} else {
		sc.countMap[hostName] = count
	}
	sc.countLock.Unlock()
}

func (sc *ScanCount) RemoveHostCountByTaskId(taskId string) {
	sc.countLock.Lock()
	for hostName, count := range sc.countMap {
		delete(count, taskId)
		if len(count) == 0 {
			delete(sc.countMap, hostName)
		}
	}
	sc.countLock.Unlock()
}

func (sc *ScanCount) GetHostMax(hostName string) int {
	sc.maxLock.RLock()
	count := sc.maxMap[hostName]
	sc.maxLock.RUnlock()
	return count
}

func (sc *ScanCount) SetHostMax(scanMaxMap map[string]int) {
	sc.maxLock.Lock()
	sc.maxMap = scanMaxMap
	sc.maxLock.Unlock()
}

func (sc *ScanCount) GetHostTotal(hostName string) int {
	sc.totalLock.RLock()
	count := 0
	for _, c := range sc.totalMap[hostName] {
		count += c
	}
	sc.totalLock.RUnlock()
	return count
}

func (sc *ScanCount) AddHostTotal(hostName, taskId string, n int) {
	if n == 0 {
		return
	}
	sc.totalLock.Lock()
	total, ok := sc.totalMap[hostName]
	if !ok {
		if n > 0 {
			sc.totalMap[hostName] = map[string]int{taskId: n}
		}
		sc.totalLock.Unlock()
		return
	}
	total[taskId] += n
	if total[taskId] <= 0 {
		delete(total, taskId)
	}
	if len(total) == 0 {
		delete(sc.totalMap, hostName)
	} else {
		sc.totalMap[hostName] = total
	}
	sc.totalLock.Unlock()
}

func (sc *ScanCount) RemoveHostTotalByTaskId(taskId string) {
	sc.totalLock.Lock()
	for hostName, total := range sc.totalMap {
		delete(total, taskId)
		if len(total) == 0 {
			delete(sc.totalMap, hostName)
		}
	}
	sc.totalLock.Unlock()
}
