// 安全组扫描任务调度
package main

import (
	"errors"
	"strings"
	"time"

	"zeroScannerGo/engine/lib/set"
	"gopkg.in/mgo.v2/bson"
)

var METHOD_FILTER = set.NewNonTS("GET", "HEAD", "OPTIONS", "PATCH", "PUT", "DELETE")

func newSecPublicSchedulerArgs() *SchedulerArgs {
	s := &SchedulerArgs{
		Name:  "secPublic",
		Queue: "secPublicQueue",
		KeyList: []string{
			"secAdd",      //安全部手动添加的外网任务
			"source",      //外网资产定时扫描
			"urlRealtime", //url实时扫描
			"urlSource",   //url存量扫描
		},
	}
	s.GetNewTaskFunc = secGetNewTask
	s.HandleTaskItemListFunc = secHandleTaskItemList
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

func newSecPrivateSchedulerArgs() *SchedulerArgs {
	s := &SchedulerArgs{
		Name:  "secPrivate",
		Queue: "secPrivateQueue",
		KeyList: []string{
			"secAdd", //安全部手动添加的内网任务
			//			"source", //内网资产定时扫描
		},
	}
	s.GetNewTaskFunc = secGetNewTask
	s.HandleTaskItemListFunc = secHandleTaskItemList
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

func secHandleTaskItemList(s *SchedulerArgs, key string, taskItemList []*TaskItem) []*TaskItem {
	// 手动添加任务不去重
	if key != "secAdd" {
		filteredTaskItemList, err := server.whiteList.filterScannedTask(taskItemList)
		if err != nil {
			server.Logger.Error(err)
			return taskItemList
		}
		return filteredTaskItemList
	}
	return taskItemList
}

func secGetNewTask(s *SchedulerArgs, key string) (*Task, error) {
	switch key {
	case "secAdd":
		return secCheckSecAddTask(s)
	case "urlRealtime":
		return secCheckUrlTask(s)
	case "source":
		return secCheckSourceTask(s)
	case "urlSource":
		return secCheckUrlSourceTask(s)
	}
	return nil, errors.New("unknown scheduler key")
}

func secCheckSecAddTask(s *SchedulerArgs) (*Task, error) {
	// 检测是否有爬完的爬虫任务，有的话丢到扫描任务队列
	err := handleSpiderTask(s)
	if err != nil {
		server.Logger.Error(err)
	}

	return defaultGetNewTask(s, "secAdd")
}

func secCheckUrlTask(s *SchedulerArgs) (*Task, error) {
	if server.scanSettings.ScanUrlRealTime {
		pocMap, err := loadPoc(nil)
		if err != nil {
			return nil, err
		}
		if len(pocMap) == 0 {
			return nil, nil
		}

		urls := server.kafkaUrlReader.Read(1000)
		if len(urls) > 0 {
			dbTask := &DBTask{
				Id:      bson.NewObjectId(),
				Thread:  MAXSCAN,
				Target:  urls,
				Service: []string{"http", "https"},
			}
			parsedTargetList, err := parseDBTarget(dbTask)
			if err != nil {
				return nil, err
			}

			// 白名单过滤
			parsedTargetList, err = server.whiteList.removeUrlWhiteList(parsedTargetList)
			if err != nil {
				server.Logger.Error(err)
				return nil, err
			}
			// 每天只扫一次的url过滤
			parsedTargetList, err = server.whiteList.removeScndOnceUrl(parsedTargetList)
			if err != nil {
				server.Logger.Error(err)
			}

			// 数据按hostname分类
			targetListMap := classifyTarget(parsedTargetList)

			task, err := NewTask(dbTask, s.DisabledPocs, targetListMap, s.Queue)
			if err != nil {
				return nil, err
			}
			task.Id = "urlscan_" + task.Id
			return task, nil
		}
	}
	return nil, nil
}

func secCheckSourceTask(s *SchedulerArgs) (*Task, error) {
	if server.scanSettings.ScanSource &&
		!server.scanSettings.ScanSourceNextTime.IsZero() &&
		time.Now().Sub(server.scanSettings.ScanSourceNextTime).Seconds() > 0 {

		pocMap, err := loadPoc(nil)
		if err != nil {
			return nil, err
		}
		if len(pocMap) == 0 {
			return nil, nil
		}

		server.Logger.Info("fetching source ...")
		// 没有取jd_public_ip 这个如果资产的端口数据不准的话，可能会漏
		source, err := server.sourceReader.Read("jd_public_port", "cloud_public_port", "yhd_public_port",
			"it_public_port", "cdn_public_port", "other_public_port", "public_domain")
		if err != nil {
			server.Logger.Error("fetch source failed", err)
			return nil, err
		}
		server.Logger.Info("fetch source succed, total:", len(source))

		if len(source) > 0 {
			dbTask := &DBTask{
				Id:     bson.NewObjectId(),
				Thread: MAXSCAN,
				Target: source,
			}
			parsedTargetList, err := parseDBTarget(dbTask)
			if err != nil {
				return nil, err
			}

			// 白名单过滤
			parsedTargetList, err = server.whiteList.removeSourceWhiteList(parsedTargetList)
			if err != nil {
				server.Logger.Error(err)
				return nil, err
			}

			// 数据按hostname分类
			targetListMap := classifyTarget(parsedTargetList)

			task, err := NewTask(dbTask, s.DisabledPocs, targetListMap, s.Queue)
			if err != nil {
				return nil, err
			}
			task.Id = "sourcescan_" + task.Id

			// 更新下次扫描时间
			server.scanSettings.ScanSourceNextTime = server.scanSettings.ScanSourceNextTime.Add(server.scanSettings.ScanSourceDelay)

			return task, nil
		}
	}
	return nil, nil
}

func secCheckUrlSourceTask(s *SchedulerArgs) (*Task, error) {
	if !server.scanSettings.ScanUrlSource {
		return nil, nil
	}
	server.Logger.Debug("secCheckUrlSourceTask")

	var allUrls []string
	for len(allUrls) < 5000 {
		index, hostInfo := server.esUrlReader.GetNextHostInfo()

		if hostInfo == nil {
			server.Logger.Debug(hostInfo.Host, "round findFinished")
			server.esUrlReader.Reset()
			break
		}

		//		server.Logger.Debug(hostInfo)

		maxScan := server.scanCount.GetHostMax(hostInfo.Host)
		if maxScan == 0 {
			maxScan = MAXSCAN
		}

		if server.scanCount.GetHostTotal(hostInfo.Host) < maxScan*10 {
			urls, err := server.esUrlReader.QueryUrl(hostInfo)
			if err != nil {
				server.Logger.Error(err)
				break
			}
			server.Logger.Debug("query finished", "index:", index, "roundCount:", hostInfo.RoundCount, hostInfo.Host, len(urls))
			urls = filterTarget(urls, METHOD_FILTER)
			server.Logger.Debug("filter finished", hostInfo.Host, len(urls))
			if len(urls) > 0 {
				allUrls = append(allUrls, urls...)
			}
			//			server.Logger.Debug(hostInfo.Host, len(urls))
		}
	}
	server.esUrlReader.Sort()
	//	server.Logger.Debug("len(allUrls):", len(allUrls))

	if len(allUrls) > 0 {
		dbTask := &DBTask{
			Id:      bson.NewObjectId(),
			Thread:  MAXSCAN,
			Target:  allUrls,
			Service: []string{"http", "https"},
		}

		parsedTargetList, err := parseDBTarget(dbTask)
		if err != nil {
			return nil, err
		}

		// 白名单过滤
		parsedTargetList, err = server.whiteList.removeUrlWhiteList(parsedTargetList)
		if err != nil {
			server.Logger.Error(err)
			return nil, err
		}
		// 每天只扫一次的url过滤
		parsedTargetList, err = server.whiteList.removeScndOnceUrl(parsedTargetList)
		if err != nil {
			server.Logger.Error(err)
		}

		// 数据按hostname分类
		targetListMap := classifyTarget(parsedTargetList)

		task, err := NewTask(dbTask, s.DisabledPocs, targetListMap, s.Queue)
		if err != nil {
			return nil, err
		}
		task.Id = "urlsourcescan_" + task.Id
		return task, nil
	}

	return nil, nil
}

//func secCheckUrlSourceTask1(s *SchedulerArgs) (*Task, error) {
//	if server.scanSettings.ScanUrlSource {
//		scrollId, err := getScrollId()
//		if err != nil {
//			return nil, err
//		}

//		urls, newScrollId, err := getUrlSource(scrollId)
//		if err != nil {
//			return nil, err
//		}

//		if newScrollId != scrollId {
//			err := saveScrollId(newScrollId)
//			if err != nil {
//				server.Logger.Error(err)
//			}
//		}
//		if newScrollId != "" {
//			err := incrEsPage()
//			if err != nil {
//				server.Logger.Error(err)
//			}
//		} else {
//			saveEsPage(0)
//		}

//		// 过滤扫描有风险的url
//		urls = filterTarget(urls, set.NewNonTS("GET", "HEAD", "OPTIONS", "PATCH", "PUT", "DELETE"))

//		if len(urls) > 0 {
//			dbTask := &DBTask{
//				Id:      bson.NewObjectId(),
//				Thread:  MAXSCAN,
//				Target:  urls,
//				Service: []string{"http", "https"},
//			}
//			parsedTargetList, _, err := parseDBTarget(dbTask)
//			if err != nil {
//				return nil, err
//			}

//			// 白名单过滤
//			parsedTargetList, err = server.whiteList.removeUrlWhiteList(parsedTargetList)
//			if err != nil {
//				server.Logger.Error(err)
//				return nil, err
//			}
//			// 每天只扫一次的url过滤
//			parsedTargetList, err = server.whiteList.removeScndOnceUrl(parsedTargetList)
//			if err != nil {
//				server.Logger.Error(err)
//			}

//			// 数据按hostname分类
//			targetListMap := classifyTarget(parsedTargetList)

//			task, err := NewTask(dbTask, s.DisabledPocs, targetListMap, s.Queue)
//			if err != nil {
//				return nil, err
//			}
//			task.Id = "urlsourcescan_" + task.Id
//			return task, nil
//		}
//	}
//	return nil, nil
//}

//func getUrlSource(scrollId string) ([]string, string, error) {
//	api := "http://mx-admin.jd.com/AssetsURLSearchAPI"
//	authId := "jGau654qxf"
//	timestamp := strconv.Itoa(int(time.Now().Unix()))
//	data := map[string]interface{}{
//		"authid":            authId,
//		"timestamp":         timestamp,
//		"sign":              util.Md5([]byte(timestamp + authId)),
//		"start_time":        time.Now().Add(time.Hour*24*-600).Unix() * 1000,
//		"end_time":          time.Now().Unix() * 1000,
//		"count":             5000,
//		"guoquan_scanner":   1,
//		"scroll_id":         scrollId,
//		"scroll_id_timeout": "86400m",
//	}
//	jsonStr, _ := json.Marshal(data)
//	resp, err := zhttp.Post(api, &zhttp.RequestOptions{
//		DialTimeout:    time.Second * 5,
//		RequestTimeout: time.Minute * 1,
//		JSON:           string(jsonStr),
//	})
//	if err != nil {
//		return nil, scrollId, err
//	}

//	body := resp.Byte()
//	resp.Close()

//	var fetchedUrls = []string{}
//	if gjson.GetBytes(body, "code").Exists() {
//		code := gjson.GetBytes(body, "code").Int()
//		if code != 200 && code != 105 {
//			errMsg := gjson.GetBytes(body, "msg").String()
//			server.Logger.Error("code:", code, "msg:", errMsg, "scrollId:", scrollId)
//			if code == 106 {
//				// 所有节点都失效了才判定为scrollId失效了
//				if strings.Contains(errMsg, "Error 404 (Not Found): all shards failed") {
//					scrollId = ""
//				}
//			}
//			return nil, scrollId, errors.New("code: " + strconv.Itoa(int(code)) + " msg: " + errMsg + "scrollId: " + scrollId)
//		}

//		data := gjson.GetBytes(body, "data").Array()
//		for _, item := range data {
//			target := item.Get("origin_msg").String()
//			if target != "" {
//				fetchedUrls = append(fetchedUrls, target)
//			}
//		}

//		if len(data) > 0 {
//			scrollId = gjson.GetBytes(body, "scroll_id").String()
//		} else {
//			esPage, err := getEsPage()
//			if err != nil {
//				server.Logger.Error(err)
//			}
//			server.Logger.Info("Es read finished, total page:", esPage)
//			scrollId = ""
//		}
//		return fetchedUrls, scrollId, nil
//	}
//	server.Logger.Error("statusCode:", resp.StatusCode(), "body:", string(body))
//	return nil, scrollId, errors.New("can't find status code from response body")
//}

/*
删除含有用户认证数据的url
删除带有登录退出标志的url
删除政府网站（在hasLogoutKey内部实现的）
匹配对应method的url
*/
func filterTarget(target []string, methods *set.SetNonTS) []string {
	result := []string{}
	dangerKeys, err := server.whiteList.getKeywordItems()
	if err != nil {
		server.Logger.Error(err)
	}
	if len(dangerKeys) == 0 {
		dangerKeys = []string{"aid", "sid", "token", "key", "uuid", "sign", "auth", "ticket"}
	}

	logoutKeys, err := server.whiteList.getLogoutItems()
	if err != nil {
		server.Logger.Error(err)
	}
	if len(logoutKeys) == 0 {
		logoutKeys = []string{"logout", "loginout", "exit", "quit"}
	}

	for _, t := range target {
		method, url, _, data := parseMethod(t)
		if !methods.Has(method) {
			continue
		}

		// 过滤参数超长的异常url
		if strings.Count(url, "]=") > 30 || strings.Count(url, "%5D=") > 30 || strings.Count(url, "&") > 200 {
			continue
		}

		// 过滤长度超长的异常域名
		tmp := strings.Split(url, "/")
		if len(tmp) > 2 && len(tmp[2]) > 100 {
			continue
		}

		if hasLogoutKey(url, logoutKeys) {
			continue
		}

		if hasDangerKey(url, dangerKeys) || hasDangerKey(data, dangerKeys) {
			continue
		}

		// 替换手机号
		t = mobilePattern.ReplaceAllString(t, "${1}=13185480117")
		// 替换邮箱
		t = emailPattern.ReplaceAllString(t, "squirreloutside${1}163.com")

		result = append(result, t)
	}
	return result
}
