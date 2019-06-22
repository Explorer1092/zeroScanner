package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"zeroScannerGo/engine"
)

//处理扫描任务结果
func saveScanResultWorker(queue string, args ...interface{}) error { //待完善
	data := args[0].(string)

	var scanResult = engine.Result{}
	json.Unmarshal([]byte(data), &scanResult)

	if scanResult.TaskId == "" {
		return errors.New("scanResult taskid is empty")
	}

	// 任务完成、正在扫描 计数
	server.schedulerManager.AddDoneCount(scanResult.TaskType, scanResult.TaskId, 1)
	// 正在扫描的域名计数减1
	server.scanCount.AddHostCount(scanResult.Params.ParsedTarget.Hostname(), scanResult.TaskId, -1)

	if scanResult.Err != "" {
		var err error
		if strings.HasPrefix(scanResult.TaskId, "urlscan") || strings.HasPrefix(scanResult.TaskId, "sourcescan") ||
			strings.HasPrefix(scanResult.TaskId, "urlsourcescan") {
			err = errAdd(scanResult)
		} else {
			err = taskUpdateErr(scanResult.TaskId, scanResult.Err)
		}
		if err != nil {
			return err
		}
	}

	var expiredHours time.Duration
	if scanResult.Vul {
		// 添加漏洞计数
		server.schedulerManager.AddVulCount(scanResult.TaskType, scanResult.TaskId, 1)

		scanResult.Host = scanResult.Params.ParsedTarget.Hostname()
		scanResult.HostType = targetType(scanResult.Host)
		// 漏洞详情插入数据库
		err := vulAdd(scanResult)
		if err != nil {
			server.Logger.Error(err)
			return err
		}
		// 高危漏洞停止扫描24小时，中低危漏洞停止扫描3天
		if scanResult.Level > "2" {
			expiredHours = time.Hour * 24
		} else {
			expiredHours = time.Hour * 24 * 3
		}
	} else if scanResult.Stop > 0 {
		expiredHours = time.Hour * time.Duration(scanResult.Stop)
		// host类型poc若未扫到漏洞，则8小时后再扫描
	} else if scanResult.PocType == engine.TypeHost {
		expiredHours = time.Hour * 8
	}

	if expiredHours > 0 {
		host, path := server.whiteList.getHostAndPathOfTarget(
			scanResult.Params.ParsedTarget.Scheme,
			scanResult.Params.ParsedTarget.Hostname(),
			scanResult.Params.ParsedTarget.Port(),
			scanResult.Params.ParsedTarget.Path,
			scanResult.PocType,
		)
		err := server.whiteList.addVulOrStopIgnoredItem(scanResult.PocName, host, path, expiredHours)
		if err != nil {
			server.Logger.Error("worker-> server.whiteList.addVulOrStopIgnoredItem Error: ", err)
		}
	}

	if scanResult.Log {
		err := logAdd(scanResult)
		if err != nil {
			return err
		}
	}
	//	server.Logger.Debug("saveVerifyResult success", scanResult.TaskId, scanResult.PocName)
	return nil
}
