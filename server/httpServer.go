package main

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"github.com/gin-gonic/gin"
)

const httpFailed = -1
const httpSucced = 0
const httpEmpty = 1

func writeResp(c *gin.Context, code int, msg string, data interface{}) { //构造http返回json
	c.Header("Access-Control-Allow-Origin", "*")
	c.JSON(http.StatusOK, gin.H{
		"code": code,
		"msg":  msg,
		"data": data,
	})
}

func agentAuth() gin.HandlerFunc { //agent下载数据鉴权
	return gin.BasicAuth(gin.Accounts{
		server.conf.AgentToken: server.conf.AgentToken,
	})
}

func apiAuth() gin.HandlerFunc { //api接口鉴权
	return gin.BasicAuth(gin.Accounts{
		server.conf.ApiToken: server.conf.ApiToken,
	})
}

/*
{
    "thread": 1000,
    "target": ["www.jd.com"], //支持域名，ip，带端口的ip，url，ip段，类似 172.17.17.1/24
	"target_key": ["public_domain", "jd_public_ip", "jd_public_port", "jd_public_ssh"],
    "type": "secPublic",
    "cookie": "key1=value1;k2=value2", //可选
    "hosts": { //可选
        "www.jd1.com": "111.111.111.111",
        "www.jd.com": "222.222.222.222"
    },
	"user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36" //可选
	"pocname": ["zabbix_sqli", "wordpress_detect"], //可选，指定使用哪些poc扫描，若该参数跟service参数均为空，则使用所有poc
	"service": ["ssh","http"] //可选，根据服务提取poc，当跟pocname同时存在时，pocname优先级更高，service将被忽略
}
*/
func httpTaskAdd(c *gin.Context) {
	dbTask := new(DBTask)
	err := c.BindJSON(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = checkAndFormatTask(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	taskId, err := taskAdd(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", []string{taskId})
}

/*
{
	"target": [
		"GET§https://www.jd.com/?a=1§application/x-www-form-urlencoded§",
		"POST§https://www.jdc.com/§application/x-www-form-urlencoded§a=1&b=2"
	],
	"cookie": "key1=value1; key2=value2",		//可选
	"hosts": {									//可选
		"www.jd.com": "127.0.0.1",
		"www.jdc.com": "127.0.0.2"
	},
	"user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36" //可选
	"filter_host":  ["www.jd.com", "www.jdc.com"]
}
*/
func httpTaskPluginAdd(c *gin.Context) {
	pluginTask := new(PluginTask)
	err := c.BindJSON(pluginTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	dbTask := new(DBTask)
	dbTask.Target = pluginTask.Target
	dbTask.Cookie = pluginTask.Cookie
	dbTask.Hosts = pluginTask.Hosts
	dbTask.Thread = MAXSCAN

	err = checkAndFormatPluginTask(dbTask, pluginTask.FilterHost)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	taskId, err := taskAdd(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", []string{taskId})
}

/*
{
	"type": "secPublic",
	"thread": 1000,
	"cookie": "a=1;b=2",
	"hosts":{
		"jdc.jd.com": "127.0.0.1"
	},
	"user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36" //可选
	"spider_info":{
		"url": ["http://woop.jd.com"],
		"allowed_domains": ["woop.jd.com"]
	}
}
*/
func httpTaskSpiderAdd(c *gin.Context) {
	dbTask := &DBTask{}
	err := c.BindJSON(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	hostList, err := checkAndFormatSpiderTask(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	spiderIds, err := addSpiderTask(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	dbTask.SpiderInfo.StartTime = time.Now()
	dbTask.SpiderInfo.SpiderIds = spiderIds
	dbTask.SpiderInfo.Status = 1
	dbTask.Status = 1

	taskId, err := taskAdd(dbTask)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	// 添加从url库查询的url列表
	go addFetchedUrls(taskId, hostList, dbTask.SpiderInfo.AllowedDomains)
	writeResp(c, httpSucced, "succed", []string{taskId})
}

/*
["taskid1", "taskid2"]
*/
func httpTaskStop(c *gin.Context) {
	taskIds := []string{}
	err := c.BindJSON(&taskIds)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	server.schedulerManager.StopTask(taskIds...)
	writeResp(c, httpSucced, "succed", nil)
}

/*
[taskid1, taskid2]
*/
func httpTaskDelete(c *gin.Context) {
	taskIds := []string{}
	err := c.BindJSON(&taskIds)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	server.schedulerManager.StopTask(taskIds...)
	err = taskDeleteByTaskIds(taskIds)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

/*
[taskid1, taskid2]
*/
func httpTaskStatus(c *gin.Context) {
	taskIds := []string{}
	err := c.BindJSON(&taskIds)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	statusMap, err := taskQueryStatusByTaskIds(taskIds)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", statusMap)
}

/*
{
    "params": {
        "method": "GET",
        "target": "http://172.20.214.73",
        "cookie": "pin=test;thor=testthor",
        "username": "tomcat", //可选
        "password": "passwd" //可选
    },
    "poc": {
        "name": "zabbix_sqlinject",
        "info": "zabbix sql注入",
        "service": "http,https",
        "level": "3",
        "type": "1",
        "username_dict": "", //可选
        "password_dict": "", //可选
        "other_dict": "", //可选
        "code": "代码",
        "params": "{\n\t\"method\":\"GET\",\n\t\"target\":\"http://172.20.214.73\",\n\t\"cookie\":\"pin=test;thor=testthor\",\n\t\"username\":\"tomcat\",\n\t\"password\":\"passwd\"\n}\n",
        "id": "1" //可选
    }
}
*/
func httpPocTest(c *gin.Context) {
	pocTestS := new(PocTestS)
	err := c.BindJSON(pocTestS)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	pocTestS.Poc.Name = strings.TrimSpace(pocTestS.Poc.Name)
	if pocTestS.Poc.Name == "" || pocTestS.Poc.Code == "" {
		writeResp(c, httpFailed, "Key fields can not be empty", nil)
		return
	}

	if pocTestS.Params.TargetId == "" {
		pocTestS.Params.TargetId = "5b172bbb4b3d8a06a73bc834"
	}

	testResult := testPoc(pocTestS.Poc, pocTestS.Params)
	writeResp(c, httpSucced, "succed", testResult)
}

/*
{
    "name": "tomcat_weakpass",
    "info": "tomcat弱口令",
    "service": "http,https",
    "level": "3",  // 低: 1, 中: 2, 高: 3, 严重: 4
    "type": "1",  // all: 0, host: 1, url: 2
    "username_dict": "telnet_username", // 可选
    "password_dict": "telnet_password",  // 可选
    "other_dict": "",  // 可选
    "code": "poc code",
}
*/
func httpPocAdd(c *gin.Context) {
	poc := new(engine.Poc)
	err := c.BindJSON(poc)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	poc.Name = strings.TrimSpace(poc.Name)
	if poc.Name == "" || poc.Code == "" || poc.Service == "" || poc.Level == "" || poc.Info == "" || poc.Type == "" {
		writeResp(c, httpFailed, "Key fields can not be empty", nil)
		return
	}

	poc.Service = strings.Replace(poc.Service, "，", ",", -1)

	id, err := addPoc(poc)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", []int64{id})
}

/*
["1", "2"]
*/
func httpPocQuery(c *gin.Context) {
	var ids []interface{}
	err := c.BindJSON(&ids)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	if len(ids) == 0 {
		writeResp(c, httpEmpty, "succed", nil)
		return
	}

	pocs, err := server.pocDb.Query(ids...)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	if len(pocs) == 0 {
		writeResp(c, httpEmpty, "succed", nil)
		return
	}
	writeResp(c, httpSucced, "succed", pocs)
}

func httpPocList(c *gin.Context) {
	pocList, err := server.pocDb.QueryAll()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", pocList)
}

func httpPocNameList(c *gin.Context) {
	pocNames, err := loadPocNames(c.Query("type"))
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
	}
	writeResp(c, httpSucced, "succed", pocNames)
}

/*
["1", "2"]
*/
func httpPocEnable(c *gin.Context) {
	var ids []interface{}
	err := c.BindJSON(&ids)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	if len(ids) == 0 {
		writeResp(c, httpSucced, "succed", nil)
		return
	}
	err = server.pocDb.Switch(1, ids...)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = initPoc()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = refreshPocs()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

/*
["1", "2"]
*/
func httpPocDisable(c *gin.Context) {
	var ids []interface{}
	err := c.BindJSON(&ids)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	if len(ids) == 0 {
		writeResp(c, httpSucced, "succed", nil)
		return
	}
	err = server.pocDb.Switch(0, ids...)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = initPoc()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = refreshPocs()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

/*
["1", "2"]
*/
func httpPocDelete(c *gin.Context) {
	var ids []interface{}
	err := c.BindJSON(&ids)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	if len(ids) == 0 {
		writeResp(c, httpSucced, "succed", nil)
		return
	}
	pocs, err := server.pocDb.Query(ids...)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	err = server.pocDb.Delete(ids...)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, p := range pocs {
		os.Remove(path.Join(engine.PocsDir, p["name"].(string)+"_"+p["hash"].(string)+".so"))
	}

	err = initPoc()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = refreshPocs()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

/*
{
    "name": "telnet_weakpass",
    "info": "telnet弱口令",
    "service": "telnet",
    "level": "3",
    "type": "1",
    "username_dict": "telnet_username",
    "password_dict": "telnet_password",
    "other_dict": "",
    "code": "poc code",
    "id": "44"
}
*/
func httpPocUpdate(c *gin.Context) {
	poc := new(engine.Poc)
	err := c.BindJSON(poc)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	poc.Name = strings.TrimSpace(poc.Name)
	if poc.Name == "" || poc.Code == "" || poc.Service == "" || poc.Level == "" || poc.Info == "" || poc.Type == "" {
		writeResp(c, httpFailed, "Key fields can not be empty", nil)
		return
	}

	poc.Service = strings.Replace(poc.Service, "，", ",", -1)

	err = updatePoc(poc)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = initPoc()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	err = refreshPocs()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

func httpPocSync(c *gin.Context) {
	err := refreshPocs()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpAgentRegister(c *gin.Context) {
	agentId := c.PostForm("id")
	schedulerName := c.PostForm("type")
	if agentId == "" || schedulerName == "" {
		writeResp(c, http.StatusBadRequest, "Agent id and type can't be empty", nil)
		return
	}

	schedulerArgs := server.schedulerManager.GetSchedulerArgs(schedulerName)
	if schedulerArgs == nil {
		writeResp(c, http.StatusBadRequest, "Agent type is not available", schedulerName)
		return
	}

	err := syncRegistInfo(agentId)
	if err != nil {
		writeResp(c, http.StatusInternalServerError, "Regist failed, the server has an error", nil)
		server.Logger.Error(err)
		return
	}

	writeResp(c, httpSucced, "regist succed", map[string]string{
		"redis_url":  server.conf.RedisUrl,
		"task_queue": schedulerArgs.Queue,
	})
}

func httpAgentDownloadPoc(c *gin.Context) {
	var fileNames []string
	err := c.BindJSON(&fileNames)
	if err != nil {
		c.String(http.StatusOK, err.Error())
		return
	}
	for i, fileName := range fileNames {
		fileNames[i] = fileName + ".so"
	}
	zipData, err := Package(engine.PocsDir, fileNames)
	if err != nil {
		server.Logger.Error(err)
		c.String(http.StatusOK, err.Error())
		return
	}
	c.Status(http.StatusOK)
	c.Header("Content-Length", strconv.Itoa(len(zipData)))
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", `attachment; filename="pocs.zip"`)
	c.Writer.Write(zipData)
}

func httpAgentDownloadSource(c *gin.Context) {
	var fileNames []string
	err := c.BindJSON(&fileNames)
	if err != nil {
		c.String(http.StatusOK, err.Error())
		return
	}
	if len(fileNames) == 0 {
		c.String(http.StatusOK, "")
		return
	}

	zipData, err := Package(engine.SourceDir, fileNames)
	if err != nil {
		c.String(http.StatusOK, err.Error())
		return
	}
	c.Status(http.StatusOK)
	c.Header("Content-Length", strconv.Itoa(len(zipData)))
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", `attachment; filename="source.zip"`)
	c.Writer.Write(zipData)
}

func httpApiDeploy(c *gin.Context) {
	zeroCData, err := ioutil.ReadFile("zeroC")
	if err != nil {
		server.Logger.Error(err)
		c.String(http.StatusOK, err.Error())
		return
	}
	c.Status(http.StatusOK)
	c.Header("Content-Length", strconv.Itoa(len(zeroCData)))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", `attachment; filename="zeroC"`)
	c.Writer.Write(zeroCData)
}

func httpSourceAdd(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	err = c.SaveUploadedFile(file, filepath.Join(engine.SourceDir, filepath.Clean(file.Filename)))
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	err = refreshSource()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", file.Filename)
}

func httpSourceList(c *gin.Context) {
	sourceList, err := fileListFromDir(engine.SourceDir)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", sourceList)
}

func httpSourceDel(c *gin.Context) {
	var fileList []string
	err := c.BindJSON(&fileList)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, fileName := range fileList {
		err := os.Remove(path.Join(engine.SourceDir, fileName))
		if err != nil {
			writeResp(c, httpFailed, err.Error(), fileName)
			return
		}
	}
	err = refreshSource()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", len(fileList))
}

func httpSourceSync(c *gin.Context) {
	err := refreshSource()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpDictAdd(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	err = c.SaveUploadedFile(file, filepath.Join(engine.DictsDir, filepath.Clean(file.Filename)))
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", file.Filename)
}

func httpDictList(c *gin.Context) {
	dictList, err := fileListFromDir(engine.DictsDir)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", dictList)
}

func httpDictDel(c *gin.Context) {
	var fileList []string
	err := c.BindJSON(&fileList)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, fileName := range fileList {
		err := os.Remove(path.Join(engine.DictsDir, fileName))
		if err != nil {
			writeResp(c, httpFailed, err.Error(), fileName)
			return
		}
	}
	writeResp(c, httpSucced, "succed", len(fileList))
}

func httpApiDebug(c *gin.Context) {
	var debugMap = map[string]interface{}{}

	// free_worker
	_, freeWorkerMap, err := getAgentWorkerMap()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	debugMap["free_worker"] = freeWorkerMap

	esPage, err := getEsPage()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	debugMap["es_page"] = esPage

	// task_map
	taskMap := map[string]map[string]interface{}{}
	server.schedulerManager.schedulerMap.Range(func(k, v interface{}) bool {
		name := k.(string)
		s := v.(*Scheduler)
		taskMap[name] = map[string]interface{}{}
		s.allTaskMap.Range(func(k, v interface{}) bool {
			taskId := k.(string)
			task := v.(*Task)
			taskMap[name][taskId] = map[string]interface{}{
				"total": task.Total,
				"count": task.Count,
				//				"running_count": task.RunningCount(),
				"done_count": task.DoneCount(),
				"vul_count":  task.VulCount(),
				"stop":       task.Stop,
				"thread":     task.Thread,
				"is_empty":   task.IsEmpty(),
				"cookie":     task.Cookie,
				"hosts":      task.Hosts,
				"queue":      task.Queue,
				"timeout":    task.TimeOut,
				"timeouted":  task.TimeOuted,
				"updatetime": task.UpdateTime,
			}
			return true
		})
		return true
	})
	debugMap["task_map"] = taskMap

	// scanCount 必须拷贝数据，否则因为同时读写map会panic
	scanCount := map[string]int{}
	scanCountMap := map[string]map[string]int{}
	server.scanCount.countLock.RLock()
	for k, v := range server.scanCount.countMap {
		var count int
		var m = map[string]int{}
		for b, c := range v {
			count += c
			m[b] = c
		}
		scanCount[k] = count
		scanCountMap[k] = m
	}
	server.scanCount.countLock.RUnlock()
	debugMap["scan_count"] = scanCount
	debugMap["scan_count_map"] = scanCountMap

	// scanMax
	scanMax := map[string]int{}
	server.scanCount.maxLock.RLock()
	for k, v := range server.scanCount.maxMap {
		scanMax[k] = v
	}
	server.scanCount.maxLock.RUnlock()
	debugMap["scan_max"] = scanMax

	// scanTotal
	scanTotal := map[string]int{}
	scanTotalMap := map[string]map[string]int{}
	server.scanCount.totalLock.RLock()
	for k, v := range server.scanCount.totalMap {
		var count int
		var m = map[string]int{}
		for b, c := range v {
			count += c
			m[b] = c
		}
		scanTotal[k] = count
		scanTotalMap[k] = m
	}
	server.scanCount.totalLock.RUnlock()
	debugMap["scan_total"] = scanTotal
	debugMap["scan_total_map"] = scanTotalMap

	// scan_settings
	debugMap["scan_settings"] = server.scanSettings

	// task_type
	taskTypeList := []string{}
	disabledPocsMap := map[string][]interface{}{}
	server.schedulerManager.schedulerMap.Range(func(k, v interface{}) bool {
		schedulerName := k.(string)
		taskTypeList = append(taskTypeList, schedulerName)

		disabledPocs := v.(*Scheduler).args.DisabledPocs
		if disabledPocs != nil {
			disabledPocsMap[schedulerName] = disabledPocs.List()
		} else {
			disabledPocsMap[schedulerName] = []interface{}{}
		}
		return true
	})
	debugMap["task_type"] = taskTypeList
	debugMap["disabled_pocs_map"] = disabledPocsMap

	// cookie_map
	debugMap["cookie_map"] = server.cookieHandler.Cookies()

	// poc_map
	//	pocMap, err := loadPoc()
	//	if err != nil {
	//		writeResp(c, httpFailed, err.Error(), nil)
	//		return
	//	}
	//	debugMap["poc_map"] = pocMap

	writeResp(c, httpSucced, "succed", debugMap)
}

func httpApiReload(c *gin.Context) {
	err := ReloadAllAgent()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpApiScanSetting(c *gin.Context) {
	var settings = new(map[string]interface{})
	err := c.BindJSON(settings)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	err = parseScanSettings(*settings)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", nil)
}

/*
{
	"secPublic":["poc001", "poc002"],
	"secPrivate":["poc001", "poc003"],
	"techPublic":["poc001"]
}
*/
func httpSchedulerPocEnable(c *gin.Context) {
	var enableMap = map[string][]string{}
	err := c.BindJSON(&enableMap)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for schedulerName, pocNameList := range enableMap {
		err := server.schedulerManager.PocSwitch(schedulerName, pocNameList, 1)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), nil)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpSchedulerPocDisable(c *gin.Context) {
	var disableMap = map[string][]string{}
	err := c.BindJSON(&disableMap)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for schedulerName, pocNameList := range disableMap {
		err := server.schedulerManager.PocSwitch(schedulerName, pocNameList, 0)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), nil)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpSchedulerList(c *gin.Context) {
	var schedulerList []string
	server.schedulerManager.schedulerMap.Range(func(k, v interface{}) bool {
		schedulerList = append(schedulerList, k.(string))
		return true
	})
	writeResp(c, httpSucced, "succed", schedulerList)
}

func httpWhiteListHostAdd(c *gin.Context) {
	var whiteList = []string{}
	err := c.BindJSON(&whiteList)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, whiteItem := range whiteList {
		err = server.whiteList.addOwnerHostItem(whiteItem)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), whiteItem)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListHostDelete(c *gin.Context) {
	err := whiteListDelete(c, "host")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListHostList(c *gin.Context) {
	whiteList, err := server.whiteList.getOwnerHostItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", whiteList)
}

func httpWhiteListPathAdd(c *gin.Context) {
	var urls = []string{}
	err := c.BindJSON(&urls)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, u := range urls {
		urlObj, err := url.Parse(u)
		if err != nil {
			if err != nil {
				writeResp(c, httpFailed, err.Error(), u)
				return
			}
		}
		host, path := server.whiteList.getHostAndPathOfTarget(urlObj.Scheme, urlObj.Hostname(), urlObj.Port(), urlObj.Path, engine.TypeUrl)
		err = server.whiteList.addOwnerPathItem(host, path)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), u)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListPathDelete(c *gin.Context) {
	err := whiteListDelete(c, "path")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListPathList(c *gin.Context) {
	whiteList, err := server.whiteList.getOwnerPathItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", whiteList)
}

func httpServiceList(c *gin.Context) {
	serviceList, err := loadPocService()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", serviceList)
}

func httpWhiteListHostNameAdd(c *gin.Context) {
	var whiteList = []string{}
	err := c.BindJSON(&whiteList)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, whiteItem := range whiteList {
		err = server.whiteList.addZeroHostItem(whiteItem)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), whiteItem)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListHostNameDelete(c *gin.Context) {
	err := whiteListDelete(c, "hostName")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListHostNameList(c *gin.Context) {
	whiteList, err := server.whiteList.getZeroHostItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", whiteList)
}

func httpWhiteListScanOnceAdd(c *gin.Context) {
	var urls = []string{}
	err := c.BindJSON(&urls)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, u := range urls {
		urlObj, err := url.Parse(u)
		if err != nil {
			if err != nil {
				writeResp(c, httpFailed, err.Error(), u)
				return
			}
		}
		host, path := server.whiteList.getHostAndPathOfTarget(urlObj.Scheme, urlObj.Hostname(), urlObj.Port(), urlObj.Path, engine.TypeUrl)
		err = server.whiteList.addScanOnceItem(host, path)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), u)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListScanOnceDelete(c *gin.Context) {
	err := whiteListDelete(c, "scanOnce")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListScanOnceList(c *gin.Context) {
	whiteList, err := server.whiteList.getScanOnceItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", whiteList)
}

func httpWhiteListKeyAdd(c *gin.Context) {
	var whiteList = []string{}
	err := c.BindJSON(&whiteList)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, whiteItem := range whiteList {
		err = server.whiteList.addKeywordItem(whiteItem)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), whiteItem)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListKeyDelete(c *gin.Context) {
	err := whiteListDelete(c, "key")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListKeyList(c *gin.Context) {
	whiteList, err := server.whiteList.getKeywordItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", whiteList)
}

func httpWhiteListLogoutKeyAdd(c *gin.Context) {
	var whiteList = []string{}
	err := c.BindJSON(&whiteList)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, whiteItem := range whiteList {
		err = server.whiteList.addLogoutItem(whiteItem)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), whiteItem)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListLogoutKeyDelete(c *gin.Context) {
	err := whiteListDelete(c, "logoutkey")
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListLogoutKeyList(c *gin.Context) {
	whiteList, err := server.whiteList.getLogoutItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", whiteList)
}

func httpScanMaxAdd(c *gin.Context) {
	var m = map[string]int{}
	err := c.BindJSON(&m)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for k, v := range m {
		err := setScanMax(k, v)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), k)
			return
		}
	}
	scanMax, err := getScanMax()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	server.scanCount.SetHostMax(scanMax)
	writeResp(c, httpSucced, "succed", nil)
}

func httpScanMaxDelete(c *gin.Context) {
	var l = []string{}
	err := c.BindJSON(&l)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	err = delScanMax(l...)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}

	scanMax, err := getScanMax()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	server.scanCount.SetHostMax(scanMax)
	writeResp(c, httpSucced, "succed", nil)
}

func httpScanMaxList(c *gin.Context) {
	writeResp(c, httpSucced, "succed", server.scanCount.maxMap)
}

func httpWhiteListHostAndKeyAdd(c *gin.Context) {
	var l = []string{}
	err := c.BindJSON(&l)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, item := range l {
		tmp := strings.SplitN(item, ":", 3)
		if len(tmp) < 2 {
			writeResp(c, httpFailed, "错误的格式，示例：www.a.com:dangerkey或www.a.com:8080:dangerkey", item)
			return
		}
		var ports []string
		var path string
		if len(tmp) < 3 {
			ports = []string{"80", "443"}
			path = tmp[1]
		} else {
			ports = []string{tmp[1]}
			path = tmp[2]
		}
		for _, port := range ports {
			err = server.whiteList.addOwnerKeyItem(tmp[0]+":"+port, path)
			if err != nil {
				writeResp(c, httpFailed, err.Error(), item)
				return
			}
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListHostAndKeyDelete(c *gin.Context) {
	var l = []string{}
	err := c.BindJSON(&l)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	for _, item := range l {
		tmp := strings.SplitN(item, ":", 3)
		if len(tmp) < 2 {
			writeResp(c, httpFailed, "错误的格式，示例：www.a.com:dangerkey或www.a.com:8080:dangerkey", item)
			return
		}
		var ports []string
		var path string
		if len(tmp) < 3 {
			ports = []string{"80", "443"}
			path = tmp[1]
		} else {
			ports = []string{tmp[1]}
			path = tmp[2]
		}
		for _, port := range ports {
			err = server.whiteList.delOwnerKeyItem(tmp[0] + ":" + port + ":" + path)
			if err != nil {
				writeResp(c, httpFailed, err.Error(), item)
				return
			}
		}
	}

	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListHostAndKeyList(c *gin.Context) {
	whiteList, err := server.whiteList.getOwnerKeyItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	writeResp(c, httpSucced, "succed", whiteList)
}

func httpWhiteListPathrgxAdd(c *gin.Context) {
	var l = []string{}
	err := c.BindJSON(&l)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	var whiteList [][]string
	for _, item := range l {
		t, err := url.Parse(item)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), item)
			return
		}
		if t.Port() != "" {
			whiteList = append(whiteList, []string{t.Host, t.Path})
		} else {
			whiteList = append(whiteList, []string{t.Hostname() + ":443", t.Path})
			whiteList = append(whiteList, []string{t.Hostname() + ":80", t.Path})
		}
	}
	for _, v := range whiteList {
		err := server.whiteList.addOwnerRgxItem(v[0], v[1])
		if err != nil {
			writeResp(c, httpFailed, err.Error(), nil)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListPathrgxDelete(c *gin.Context) {
	var l = []string{}
	err := c.BindJSON(&l)
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
		return
	}
	var whiteList []string
	for _, item := range l {
		t, err := url.Parse(item)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), item)
			return
		}
		if t.Port() != "" {
			whiteList = append(whiteList, t.Host+":"+t.Path)
		} else {
			whiteList = append(whiteList, t.Hostname()+":443:"+t.Path)
			whiteList = append(whiteList, t.Hostname()+":80:"+t.Path)
		}
	}
	for _, v := range whiteList {
		err := server.whiteList.delOwnerRgxItem(v)
		if err != nil {
			writeResp(c, httpFailed, err.Error(), nil)
			return
		}
	}
	writeResp(c, httpSucced, "succed", nil)
}

func httpWhiteListPathrgxList(c *gin.Context) {
	l, err := server.whiteList.getOwnerRgxItems()
	if err != nil {
		writeResp(c, httpFailed, err.Error(), nil)
	}
	writeResp(c, httpSucced, "succed", l)
}

func newHttpServer(serverHttpPort int) error {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Status(http.StatusOK)
		}
	})

	agentGroup := r.Group("/agent", agentAuth())
	agentGroup.POST("/register", httpAgentRegister)
	agentGroup.POST("/download/poc", httpAgentDownloadPoc)
	agentGroup.POST("/download/source", httpAgentDownloadSource)

	apiGroup := r.Group("/", apiAuth())
	apiGroup.POST("/poc/add", httpPocAdd)
	apiGroup.POST("/poc/test", httpPocTest)
	apiGroup.POST("/poc/query", httpPocQuery)
	apiGroup.POST("/poc/enable", httpPocEnable)
	apiGroup.POST("/poc/disable", httpPocDisable)
	apiGroup.POST("/poc/delete", httpPocDelete)
	apiGroup.POST("/poc/update", httpPocUpdate)
	apiGroup.GET("/poc/sync", httpPocSync)
	apiGroup.GET("/poc/list", httpPocList)
	apiGroup.GET("/poc/namelist", httpPocNameList)

	apiGroup.POST("/source/add", httpSourceAdd)
	apiGroup.GET("/source/list", httpSourceList)
	apiGroup.POST("/source/delete", httpSourceDel)
	apiGroup.GET("/source/sync", httpSourceSync)

	apiGroup.POST("/dict/add", httpDictAdd)
	apiGroup.GET("/dict/list", httpDictList)
	apiGroup.POST("/dict/delete", httpDictDel)

	apiGroup.GET("/api/debug", httpApiDebug)
	apiGroup.GET("/api/reload", httpApiReload)
	apiGroup.POST("/api/scan/setting", httpApiScanSetting)
	apiGroup.GET("/api/deploy", httpApiDeploy)

	apiGroup.POST("/scheduler/poc/enable", httpSchedulerPocEnable)
	apiGroup.POST("/scheduler/poc/disable", httpSchedulerPocDisable)
	apiGroup.GET("/scheduler/list", httpSchedulerList)

	apiGroup.POST("/task/add", httpTaskAdd)
	apiGroup.POST("/task/stop", httpTaskStop)
	apiGroup.POST("/task/status", httpTaskStatus)
	apiGroup.POST("/task/delete", httpTaskDelete)
	apiGroup.POST("/task/plugin/add", httpTaskPluginAdd)
	apiGroup.POST("/task/spider/add", httpTaskSpiderAdd)

	//	apiGroup.POST("/task/query", httpTaskQuery)

	apiGroup.POST("/whitelist/host/add", httpWhiteListHostAdd)
	apiGroup.POST("/whitelist/host/delete", httpWhiteListHostDelete)
	apiGroup.GET("/whitelist/host/list", httpWhiteListHostList)

	apiGroup.POST("/whitelist/path/add", httpWhiteListPathAdd)
	apiGroup.POST("/whitelist/path/delete", httpWhiteListPathDelete)
	apiGroup.GET("/whitelist/path/list", httpWhiteListPathList)

	apiGroup.POST("/whitelist/hostname/add", httpWhiteListHostNameAdd)
	apiGroup.POST("/whitelist/hostname/delete", httpWhiteListHostNameDelete)
	apiGroup.GET("/whitelist/hostname/list", httpWhiteListHostNameList)

	apiGroup.POST("/whitelist/scanonce/add", httpWhiteListScanOnceAdd)
	apiGroup.POST("/whitelist/scanonce/delete", httpWhiteListScanOnceDelete)
	apiGroup.GET("/whitelist/scanonce/list", httpWhiteListScanOnceList)

	apiGroup.POST("/whitelist/key/add", httpWhiteListKeyAdd)
	apiGroup.POST("/whitelist/key/delete", httpWhiteListKeyDelete)
	apiGroup.GET("/whitelist/key/list", httpWhiteListKeyList)

	apiGroup.POST("/whitelist/logoutkey/add", httpWhiteListLogoutKeyAdd)
	apiGroup.POST("/whitelist/logoutkey/delete", httpWhiteListLogoutKeyDelete)
	apiGroup.GET("/whitelist/logoutkey/list", httpWhiteListLogoutKeyList)

	apiGroup.POST("whitelist/hostandkey/add", httpWhiteListHostAndKeyAdd)
	apiGroup.POST("whitelist/hostandkey/delete", httpWhiteListHostAndKeyDelete)
	apiGroup.GET("whitelist/hostandkey/list", httpWhiteListHostAndKeyList)

	apiGroup.POST("whitelist/pathrgx/add", httpWhiteListPathrgxAdd)
	apiGroup.POST("whitelist/pathrgx/delete", httpWhiteListPathrgxDelete)
	apiGroup.GET("whitelist/pathrgx/list", httpWhiteListPathrgxList)

	apiGroup.POST("/scanmax/add", httpScanMaxAdd)
	apiGroup.POST("/scanmax/delete", httpScanMaxDelete)
	apiGroup.GET("/scanmax/list", httpScanMaxList)

	apiGroup.GET("/service/list", httpServiceList)

	var err error
	go func() {
		err = r.Run(":" + strconv.Itoa(serverHttpPort))
	}()
	time.Sleep(time.Second)
	return err
}
