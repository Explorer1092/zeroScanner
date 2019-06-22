package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/set"
	"zeroScannerGo/engine/lib/zhttp"
	"zeroScannerGo/lib/util"
	"github.com/tidwall/gjson"
)

var (
	cidrP  = regexp.MustCompile(`\A\d{1,3}(\.\d{1,3}){3}/\d{1,2}\z`)
	keyMap = map[string]string{
		"url_post":    "POST",
		"url_get":     "GET",
		"url_head":    "HEAD",
		"url_options": "OPTIONS",
		"url_delete":  "DELETE",
		"url_patch":   "PATCH",
		"url_put":     "PUT",
	}
)

func formatTarget(dbTask *DBTask, known *set.SetNonTS) error {
	var targetList []string
	for _, target := range dbTask.Target {
		// 不是网段，则直接添加
		if !cidrP.MatchString(target) {
			if !known.Has(target) {
				targetList = append(targetList, target)
				known.Add(target)
			}
		} else {
			hosts, err := parseCidr(target)
			if err != nil {
				return err
			}
			for _, ip := range hosts {
				if !known.Has(ip) {
					targetList = append(targetList, ip)
					known.Add(ip)
				}
			}
		}
	}
	dbTask.Target = targetList

	return nil
}

// 解析targetkey，提取资产数据
func parseTargetKey(dbTask *DBTask, known *set.SetNonTS) error {
	var targetKey = []string{}
	// 过滤掉url资产
	for _, key := range dbTask.TargetKey {
		if !strings.HasPrefix(key, "url_") {
			targetKey = append(targetKey, key)
		}
	}

	if len(targetKey) > 0 {
		server.Logger.Info("fetching source", targetKey, " ...")
		source, err := server.sourceReader.sourceAPI.GetSource(targetKey...)
		if err != nil {
			server.Logger.Error("fetch source failed", err)
			return err
		}
		server.Logger.Info("fetch source succed, total:", len(source))

		formatedSource, err := formatSource(source)
		if err != nil {
			return err
		}

		for _, sourceUrl := range formatedSource {
			if !known.Has(sourceUrl) {
				dbTask.Target = append(dbTask.Target, sourceUrl)
				known.Add(sourceUrl)
			}
		}
	}

	return nil
}

func parseUrlReader(dbTask *DBTask) (*ESUrlReader, *set.SetNonTS, error) {
	if len(dbTask.TargetKey) > 0 {
		methodFilter := set.NewNonTS()

		for _, key := range dbTask.TargetKey {
			if key == "url_all" {
				for _, v := range keyMap {
					methodFilter.Add(v)
				}
				break
			}
			if keyMap[key] != "" {
				methodFilter.Add(keyMap[key])
			}
		}

		if methodFilter.Size() > 0 {
			urlReader := NewEsUrlReader()
			err := urlReader.RefreshHostList()
			if err != nil {
				return nil, nil, err
			}
			return urlReader, methodFilter, nil
		}
	}
	return nil, nil, nil
}

func parseDBTarget(dbTask *DBTask) ([]ParsedTarget, error) {
	known := set.NewNonTS()
	err := formatTarget(dbTask, known)
	if err != nil {
		return nil, err
	}

	err = parseTargetKey(dbTask, known)
	if err != nil {
		return nil, err
	}
	known.Clear()

	parsedTargetList := parseTarget(dbTask.Target)

	return parsedTargetList, nil
}

func parseTarget(targetList []string) []ParsedTarget {
	var parsedTargetList []ParsedTarget
	for _, t := range targetList {
		method, target, contentType, data := parseMethod(t)
		urlObj, _, err := checkAndParseTarget(target)
		if err != nil {
			//			server.Logger.Error(err)
			continue
		}
		parsedTargetList = append(parsedTargetList, ParsedTarget{
			Method:      method,
			Target:      target,
			ContentType: contentType,
			Data:        data,
			UrlObj:      *urlObj,
		})
	}
	return parsedTargetList
}

func classifyTarget(targetList []ParsedTarget) map[string][]ParsedTarget {
	targetListMap := map[string][]ParsedTarget{}
	for _, parsedTarget := range targetList {
		hostname := parsedTarget.UrlObj.Hostname()
		targetListMap[hostname] = append(targetListMap[hostname], parsedTarget)
	}
	return targetListMap
}

func NewTask(dbTask *DBTask, disabledPocs *set.Set, targetListMap map[string][]ParsedTarget, queue string) (*Task, error) {
	pocIterList := []*Iter{}
	for pocName, pocIter := range server.pocIterMap {
		if disabledPocs.Has(pocName) {
			continue
		}
		if len(dbTask.PocName) > 0 {
			if !contains(dbTask.PocName, pocName) {
				continue
			}
		}
		pocIterList = append(pocIterList, pocIter)
	}

	if len(pocIterList) == 0 {
		return nil, errors.New("无可扫target或无匹配的poc，请检查目标是否被白名单过滤或者poc类型是否匹配")
	}

	task := &Task{
		Id:          dbTask.Id.Hex(),
		Thread:      dbTask.Thread,
		TimeOut:     time.Minute * 120,
		Queue:       queue,
		Cookie:      dbTask.Cookie,
		UserAgent:   dbTask.UserAgent,
		Hosts:       dbTask.Hosts,
		TargetIdMap: map[string]string{},
		Scaned:      set.NewNonTS(),
		pocIterList: pocIterList,
	}

	for ip, targetList := range targetListMap {
		ti := new(TargetIter)
		ti.Init(task.pocIterList, targetList)
		task.TaskIter.Store(ip, ti)

		//		server.Logger.Debug("len(targetList):", len(targetList), "len(task.pocIterList):", len(task.pocIterList), "ti.Total:", ti.Total)

		task.Total += ti.Total
	}

	return task, nil
}

// 将poc解析为poc迭代器
func parsePoc(poc engine.Poc) (*Iter, error) {
	var (
		err                                   error
		userNameList, passWordList, otherList []string
	)
	if poc.UsernameDict != "" {
		userNameList, err = util.ReadLines(filepath.Join(engine.DictsDir, filepath.Clean(poc.UsernameDict)))
		if err != nil {
			return nil, err
		}
	}
	if poc.PasswordDict != "" {
		passWordList, err = util.ReadLines(filepath.Join(engine.DictsDir, filepath.Clean(poc.PasswordDict)))
		if err != nil {
			return nil, err
		}
	}
	if poc.OtherDict != "" {
		otherList, err = util.ReadLines(filepath.Join(engine.DictsDir, filepath.Clean(poc.OtherDict)))
		if err != nil {
			return nil, err
		}
	}
	pocIter := NewPocIter(poc.Name, poc.Type, poc.Services, userNameList, passWordList, otherList)
	return pocIter, nil
}

func getQueueCountAndWorker(schedulerName string, queue string) (int, int, int, error) {
	queueCount, err := getQueueCount(queue)
	if err != nil {
		server.Logger.Error(err)
		return 0, 0, 0, err
	}

	totalWorker, freeWorker, err := getSchedulerWorker(schedulerName)
	if err != nil {
		server.Logger.Error(err)
		return 0, 0, 0, err
	}
	return queueCount, totalWorker, freeWorker, nil
}

func handleSpiderTaskTimeout(spiderTask *DBTask) {
	err := taskUpdateErr(spiderTask.Id.Hex(), "爬虫爬取超时")
	if err != nil {
		server.Logger.Error(spiderTask.Id.Hex(), err)
	}

	// 提取爬虫url数据
	spiderUrls, err := getSpiderResult(spiderTask.SpiderInfo.SpiderIds)
	if err != nil {
		server.Logger.Error(err)
		return
	}

	// 检查提取url存量数据是否成功，当爬虫超时的时候，如果url存量数据还未提取完，那url存量数据也算提取超时
	if !spiderTask.SpiderInfo.UrlFetched {
		err = taskUpdateErr(spiderTask.Id.Hex(), "url提取失败")
		if err != nil {
			server.Logger.Error(spiderTask.Id.Hex(), err)
		}
	}

	allUrls := mergeSpiderAndFetchedUrls(spiderUrls, spiderTask.SpiderInfo.FetchedUrls)
	if len(allUrls) == 0 {
		err = taskUpdateStatus(spiderTask.Id.Hex(), -1)
		if err != nil {
			server.Logger.Error(spiderTask.Id.Hex(), err)
		}
		return
	}

	err = updateSpiderTaskTarget(spiderTask.Id, -1, allUrls)
	if err != nil {
		server.Logger.Error(err)
	}
}

func getStatus(statusList []string) string {
	var pending, running, ending bool
	for _, status := range statusList {
		if status == "pending" {
			pending = true
		} else if status == "running" {
			running = true
		} else {
			ending = true
		}
	}
	if pending && !running && !ending {
		return "running"
	}
	if ending && !pending && !running {
		return "ending"
	}
	return "running"
}

func handleSpiderTask(s *SchedulerArgs) error {
	spiderTasks, err := getRunningSpiderTask(s.Name, 100)
	if err != nil {
		return err
	}

	if len(spiderTasks) > 0 {
		var spiderIdsList [][]string
		for _, spiderTask := range spiderTasks {
			spiderIdsList = append(spiderIdsList, spiderTask.SpiderInfo.SpiderIds)
		}

		spiderStatusList, err := checkSpiderTaskStatus(spiderIdsList)
		if err != nil {
			return err
		}

		// 检查爬取是否完成
		for i, statusList := range spiderStatusList {
			spiderTask := spiderTasks[i]
			status := getStatus(statusList)
			if status == "pending" {
				// 爬虫队列中等待超时
				if time.Now().Sub(spiderTask.SpiderInfo.StartTime) > time.Minute*60 {
					handleSpiderTaskTimeout(&spiderTask)
				}
				continue
			} else if status == "running" {
				if spiderTask.SpiderInfo.Status == 1 {
					err = updateSpiderTaskStartTime(spiderTask.Id)
					if err != nil {
						server.Logger.Error(spiderTask.Id.Hex(), err)
					}
				}
				if time.Now().Sub(spiderTask.SpiderInfo.StartTime) > time.Minute*60 {
					handleSpiderTaskTimeout(&spiderTask)
				}
				continue
			}

			// 如果还没有提取完url存量数据
			if !spiderTasks[i].SpiderInfo.UrlFetched {
				// 检测url存量数据提取超时
				if time.Now().Sub(spiderTasks[i].CreateTime) > time.Minute*30 {
					err = taskUpdateErr(spiderTasks[i].Id.Hex(), "url提取超时")
					if err != nil {
						server.Logger.Error(spiderTasks[i].Id.Hex(), err)
					}
					// 否则等待下次检测
				} else {
					continue
				}
			}

			spiderIds := spiderIdsList[i]
			spiderUrls, err := getSpiderResult(spiderIds)
			if err != nil {
				server.Logger.Error(err)
				continue
			}

			server.Logger.Debug(spiderIds)
			// 合并爬虫结果和提取的url数据
			server.Logger.Debug("len(spiderUrls):", spiderIds, len(spiderUrls), len(spiderTasks[i].SpiderInfo.FetchedUrls))
			allUrls := mergeSpiderAndFetchedUrls(spiderUrls, spiderTasks[i].SpiderInfo.FetchedUrls)
			server.Logger.Debug("len(allUrls):", len(allUrls))

			err = updateSpiderTaskTarget(spiderTasks[i].Id, 100, allUrls)
			if err != nil {
				server.Logger.Error(err)
			}
		}
	}

	return nil
}

func addSpiderTask(task *DBTask) ([]string, error) {
	api := "http://mx-admin.jd.com/SpiderAPIPushTask"
	data := map[string]interface{}{
		"url":             task.SpiderInfo.Urls,
		"cookie":          task.Cookie,
		"hosts":           task.Hosts,
		"user_agent":      task.UserAgent,
		"allowed_domains": task.SpiderInfo.AllowedDomains,
		"is_private":      false,
	}
	if strings.Contains(task.Type, "Private") {
		data["is_private"] = true
	}

	respData, err := sendToApi(api, data)
	if err != nil {
		return nil, err
	}
	var spiderIds []string
	for _, obj := range respData.Array() {
		spiderId := obj.String()
		if spiderId == "" {
			return nil, errors.New("empty spiderid")
		}
		spiderIds = append(spiderIds, spiderId)
	}
	return spiderIds, nil
}

func checkSpiderTaskStatus(spiderIdsList [][]string) ([][]string, error) {
	api := "http://mx-admin.jd.com/SpiderAPIGetTaskStatus"
	spiderIds := []string{}
	for _, item := range spiderIdsList {
		for _, spiderId := range item {
			spiderIds = append(spiderIds, spiderId)
		}
	}

	data := map[string]interface{}{"taskids": spiderIds}
	respData, err := sendToApi(api, data)
	if err != nil {
		return nil, err
	}

	statusList := respData.Array()
	if len(statusList) < len(spiderIds) {
		return nil, errors.New("response length less than query length, response length: " +
			strconv.Itoa(len(statusList)) + ", query length: " + strconv.Itoa(len(spiderIds)))
	}

	var index int
	var spiderStatusList = make([][]string, len(spiderIdsList))
	for i, item := range spiderIdsList {
		spiderStatusList[i] = make([]string, len(item))
		for j, _ := range item {
			spiderStatusList[i][j] = statusList[index].String()
			index++
		}
	}

	return spiderStatusList, nil
}

func getSpiderResult(spiderIds []string) ([]string, error) {
	api := "http://mx-admin.jd.com/SpiderAPIGetTaskResult"
	data := map[string]interface{}{"taskids": spiderIds}
	respData, err := sendToApi(api, data)
	if err != nil {
		return nil, err
	}

	server.Logger.Debug(respData.String())

	urls := []string{}
	for _, obj := range respData.Array() {
		urls = append(urls, obj.String())
	}
	return urls, nil
}

func sendToApi(api string, data map[string]interface{}) (*gjson.Result, error) {
	authId := "gPv94qxf"
	timestamp := strconv.Itoa(int(time.Now().Unix()))
	data["authid"] = authId
	data["timestamp"] = timestamp
	data["sign"] = util.Md5([]byte(timestamp + authId))

	jsonStr, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	resp, err := zhttp.Post(api, &zhttp.RequestOptions{
		DialTimeout:    time.Second * 5,
		RequestTimeout: time.Minute * 2,
		JSON:           string(jsonStr),
	})
	if err != nil {
		return nil, err
	}
	body := resp.Byte()
	resp.Close()

	if gjson.GetBytes(body, "code").Exists() {
		code := gjson.GetBytes(body, "code").Int()
		if code != 0 {
			errMsg := gjson.GetBytes(body, "error_msg").String()
			return nil, errors.New(errMsg)
		}
		data := gjson.GetBytes(body, "data")
		return &data, nil
	}
	server.Logger.Error("statusCode:", resp.StatusCode(), "body:", string(body))
	return nil, errors.New("can't find status code from response body")
}

func addFetchedUrls(taskId string, hostList, allowedDomains []string) error {
	server.Logger.Debug(taskId, "fetchUrls ...")
	s := set.NewNonTS()
	for _, host := range hostList {
		s.Add(host)
	}
	for _, domain := range allowedDomains {
		if !s.Has(domain) {
			hostList = append(hostList, domain)
			s.Add(domain)
		}
	}
	s.Clear()

	var fetchedUrls = []string{}
	for _, host := range hostList {
		urls, err := fetchUrlByHost(host)
		if err != nil {
			server.Logger.Error(err)
			continue
		}
		fetchedUrls = append(fetchedUrls, urls...)
	}
	server.Logger.Debug(taskId, "fetched succed, total:", len(fetchedUrls))
	return updateSpiderTaskFetchedUrls(taskId, fetchedUrls)
}

func fetchUrlByHost(host string) ([]string, error) {
	api := "http://mx-admin.jd.com/AssetsURLSearchAPI"
	authId := "jGau654qxf"
	timestamp := strconv.Itoa(int(time.Now().Unix()))
	data := map[string]interface{}{
		"authid":          authId,
		"timestamp":       timestamp,
		"sign":            util.Md5([]byte(timestamp + authId)),
		"start_time":      time.Now().Add(time.Hour*24*-7).Unix() * 1000,
		"end_time":        time.Now().Unix() * 1000,
		"count":           3000,
		"guoquan_scanner": 1,
		"host":            host,
	}
	jsonStr, _ := json.Marshal(data)
	resp, err := zhttp.Post(api, &zhttp.RequestOptions{
		DialTimeout:    time.Second * 5,
		RequestTimeout: time.Minute * 1,
		JSON:           string(jsonStr),
	})
	if err != nil {
		return nil, err
	}

	body := resp.Byte()
	resp.Close()

	var fetchedUrls = []string{}
	if gjson.GetBytes(body, "code").Exists() {
		code := gjson.GetBytes(body, "code").Int()
		if code != 200 && code != 105 {
			errMsg := gjson.GetBytes(body, "msg").String()
			server.Logger.Error("code:", code, "msg:", errMsg)
			return nil, errors.New(errMsg)
		}
		data := gjson.GetBytes(body, "data")
		for _, item := range data.Array() {
			target := item.Get("origin_msg").String()
			if target != "" {
				fetchedUrls = append(fetchedUrls, target)
			}
		}
		return fetchedUrls, nil
	}
	server.Logger.Error("statusCode:", resp.StatusCode(), "body:", string(body))
	return nil, errors.New("can't find status code from response body")
}

func mergeSpiderAndFetchedUrls(spiderUrls, fetchedUrls []string) []string {
	var (
		s         = set.NewNonTS()
		whiteList = map[string]bool{
			"action":     true,
			"mod":        true,
			"controller": true,
			"model":      true,
			"method":     true,
			"functionId": true,
			"_format_":   true,
		}
	)
	// 计算url hash的方法
	hash := func(target string) (string, error) {
		method, urlStr, _, _ := parseMethod(target)
		urlObj, err := url.Parse(urlStr)
		if err != nil {
			return "", err
		}

		keyStr := method + urlObj.Host + urlObj.Path
		var queryNameList []string
		for k, v := range urlObj.Query() {
			if whiteList[k] {
				keyStr += k + "=" + v[0]
				continue
			}
			queryNameList = append(queryNameList, k)
		}
		sort.Strings(queryNameList)
		keyStr += strings.Join(queryNameList, "&")
		return util.Md5([]byte(keyStr)), nil
	}

	for _, target := range spiderUrls {
		hashStr, err := hash(target)
		if err != nil {
			continue
		}
		s.Add(hashStr)
	}

	for _, target := range fetchedUrls {
		hashStr, err := hash(target)
		if err != nil {
			continue
		}
		if !s.Has(hashStr) {
			spiderUrls = append(spiderUrls, target)
		}
	}
	s.Clear()
	return spiderUrls
}

func ParamsHash(params engine.Params) string {
	return util.Md5([]byte(params.Method + params.ParsedTarget.Scheme + params.ParsedTarget.Host + params.ParsedTarget.Path +
		params.ParsedTarget.RawQuery + params.ParsedTarget.Fragment + params.ContentType + params.Data))
}
