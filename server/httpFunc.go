package main

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"

	"github.com/gin-gonic/gin"
	"gopkg.in/fatih/set.v0"
)

func whiteListDelete(c *gin.Context, whiteListType string) error {
	var (
		items   = []string{}
		delFunc func(string) error
	)
	err := c.BindJSON(&items)
	if err != nil {
		return err
	}
	switch whiteListType {
	case "hostName":
		delFunc = server.whiteList.delZeroHostItem
	case "host":
		delFunc = server.whiteList.delOwnerHostItem
	case "path":
		delFunc = server.whiteList.delOwnerPathItem
	case "key":
		delFunc = server.whiteList.delKeywordItem
	case "logoutkey":
		delFunc = server.whiteList.delLogoutItem
	case "scanOnce":
		delFunc = server.whiteList.delScanOnceItem
	default:
		return nil
	}
	if delFunc != nil {
		for _, item := range items {
			err := delFunc(item)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func addPoc(poc *engine.Poc) (int64, error) {
	if poc.Type != engine.TypeAll && poc.Type != engine.TypeHost && poc.Type != engine.TypeUrl {
		return 0, errors.New("Unknown poc type")
	}
	poc.Hash = util.Md5([]byte(poc.Code))
	id, err := server.pocDb.Add(poc.Name, poc.Code, poc.Type, poc.Info, poc.Service, poc.Level, poc.UsernameDict, poc.PasswordDict, poc.OtherDict, poc.Suggestion, poc.Hash)
	if err != nil {
		return 0, err
	}

	if !soFileExist(poc.Name, poc.Hash) {
		_, err = compilePoc(poc.Name, poc.Code, poc.Hash)
		if err != nil {
			server.pocDb.Delete(id)
			return 0, err
		}
	}

	return id, nil
}

func updatePoc(poc *engine.Poc) error {
	if poc.Type != engine.TypeAll && poc.Type != engine.TypeHost && poc.Type != engine.TypeUrl {
		return errors.New("Unknown poc type")
	}
	poc.Hash = util.Md5([]byte(poc.Code))
	if soFileExist(poc.Name, poc.Hash) {
		err := server.pocDb.Update(poc.Name, poc.Code, poc.Type, poc.Info, poc.Service, poc.Level, poc.UsernameDict, poc.PasswordDict, poc.OtherDict, poc.Suggestion, poc.Hash, poc.Id)
		if err != nil {
			return err
		}
	} else {
		soFile, err := compilePoc(poc.Name, poc.Code, poc.Hash)
		if err != nil {
			return err
		}

		err = server.pocDb.Update(poc.Name, poc.Code, poc.Type, poc.Info, poc.Service, poc.Level, poc.UsernameDict, poc.PasswordDict, poc.OtherDict, poc.Suggestion, poc.Hash, poc.Id)
		if err != nil {
			os.Remove(soFile)
			return err
		}

		fileList, err := fileListFromDir(engine.PocsDir)
		if err != nil {
			return nil
		}

		//删除旧的so文件
		for _, fileName := range fileList {
			pocName, hash := splitSoFile(fileName)
			if pocName == poc.Name && hash != poc.Hash {
				os.Remove(path.Join(engine.PocsDir, fileName))
			}
		}
	}
	return nil
}

func testPoc(poc engine.Poc, params engine.Params) TestResult {
	var testResult = TestResult{}
	parsedTarget, _, err := checkAndParseTarget(params.Target)
	if err != nil {
		testResult.Err = err.Error()
		return testResult
	}
	if parsedTarget.Scheme == "" {
		parsedTarget.Scheme = "http"
	}
	params.ParsedTarget = *parsedTarget

	if params.Cookie == "" {
		params.Cookie = server.cookieHandler.GetCookie("")
	}

	poc.Hash = util.Md5([]byte(poc.Code))

	if soFileExist(poc.Name, poc.Hash) {
		soFile := path.Join(engine.PocsDir, poc.Name+"_"+poc.Hash+".so")
		testResult = testPocInSubProcess(soFile, server.cookieHandler.Cookies(), params)
	} else {
		soFile, err := compilePoc(poc.Name, poc.Code, poc.Hash)
		if err != nil {
			testResult.Err = err.Error()
			return testResult
		}
		testResult = testPocInSubProcess(soFile, server.cookieHandler.Cookies(), params)
		os.Remove(soFile)
	}
	return testResult
}

// 同步poc到所有节点
func refreshPocs() error {
	pocMap, err := loadPoc(nil)
	if err != nil {
		return err
	}
	err = SyncToAgent(nil, nil, pocMap)
	if err != nil {
		return err
	}
	return nil
}

func refreshSource() error {
	sourceMap, err := loadSourceMap()
	if err != nil {
		return err
	}
	err = SyncToAgent(nil, sourceMap, nil)
	if err != nil {
		return err
	}
	return nil
}

func parseScanSettings(settings map[string]interface{}) error {
	sourceI := settings["source"]
	source, ok := sourceI.(map[string]interface{})
	if ok {
		scan, ok := source["scan"].(bool)
		if ok {
			server.scanSettings.ScanSource = scan
		}
		delay, ok := source["delay"].(float64)
		if ok {
			server.scanSettings.ScanSourceDelay = time.Duration(int64(delay)) * time.Hour
		}
		nextTime, ok := source["next_time"].(string)
		if ok {
			t, err := time.ParseInLocation("2006-01-02 15:04:05", nextTime, time.Local)
			if err != nil {
				return err
			}
			server.scanSettings.ScanSourceNextTime = t
		}
	}

	urlRealTimeI := settings["url_realtime"]
	urlRealTime, ok := urlRealTimeI.(map[string]interface{})
	if ok {
		scan, ok := urlRealTime["scan"].(bool)
		if ok {
			server.scanSettings.ScanUrlRealTime = scan
		}
	}

	urlSourceI := settings["url_source"]
	urlSource, ok := urlSourceI.(map[string]interface{})
	if ok {
		scan, ok := urlSource["scan"].(bool)
		if ok {
			server.scanSettings.ScanUrlSource = scan
		}
		//		delay, ok := urlSource["delay"].(float64)
		//		if ok {
		//			server.scanSettings.ScanUrlTimingDelay = time.Duration(int64(delay)) * time.Hour
		//		}
		//		nextTime, ok := urlSource["next_time"].(string)
		//		if ok {
		//			t, err := time.ParseInLocation("2006-01-02 15:04:05", nextTime, time.Local)
		//			if err != nil {
		//				return err
		//			}
		//			server.scanSettings.ScanUrlTimingNextTime = t
		//		}
	}
	return nil
}

func IsFilterHostPublic(filterHost []string, hosts map[string]string) (public bool, err error) {
	for i, host := range filterHost {
		ip := hosts[host]
		if ip == "" {
			ip, err = server.dnsCache.FetchOneString(host)
			if err != nil {
				return
			}
		}
		nip := net.ParseIP(ip)

		if i == 0 {
			public = IsPublicIP(nip)
		} else {
			if IsPublicIP(nip) != public {
				err = errors.New("扫描目标必须全为外网或全为内网, " + host + " 跟其他目标网络类型不匹配")
				return
			}
		}
	}
	return
}

func checkAndFormatTask(dbTask *DBTask) error {
	if len(dbTask.Target) == 0 && len(dbTask.TargetKey) == 0 {
		return errors.New("扫描目标不能为空")
	}

	return baseCheckAndFormatTask(dbTask)
}

func baseCheckAndFormatTask(dbTask *DBTask) error {
	if server.schedulerManager.GetSchedulerArgs(dbTask.Type) == nil {
		return errors.New(`错误的任务类型，请检查"` + dbTask.Type + `"`)
	}

	for domain, ip := range dbTask.Hosts {
		delete(dbTask.Hosts, domain)

		domain = strings.TrimSpace(domain)
		ip = strings.TrimSpace(ip)
		dbTask.Hosts[domain] = ip

		dt := targetType(domain)
		if dt != "domain" {
			return errors.New("hosts填写错误，请检查" + domain + "是否是域名")
		}
		it := targetType(ip)
		if it != "ip" {
			return errors.New("hosts填写错误，请检查" + ip + "是否是ip")
		}
	}

	dbTask.Cookie = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(dbTask.Cookie), "Cookie:"), "cookie:")

	if dbTask.Thread <= 0 {
		dbTask.Thread = MAXSCAN
	}

	if !strings.HasPrefix(dbTask.Type, "sec") {
		if dbTask.Thread > 1000 {
			dbTask.Thread = 1000
		}
	}

	return nil
}

func checkAndFormatPluginTask(dbTask *DBTask, filterHost []string) error {
	for domain, ip := range dbTask.Hosts {
		delete(dbTask.Hosts, domain)

		domain = strings.TrimSpace(domain)
		ip = strings.TrimSpace(ip)
		dbTask.Hosts[domain] = ip

		dt := targetType(domain)
		if dt != "domain" {
			return errors.New("hosts填写错误，请检查" + domain + "是否是域名")
		}
		it := targetType(ip)
		if it != "ip" {
			return errors.New("hosts填写错误，请检查" + ip + "是否是ip")
		}
	}

	public, err := IsFilterHostPublic(filterHost, dbTask.Hosts)
	if err != nil {
		return err
	}

	if public {
		dbTask.Type = "techPublic"
	} else {
		dbTask.Type = "techPrivate"
	}

	if server.schedulerManager.GetSchedulerArgs(dbTask.Type) == nil {
		return errors.New(`错误的任务类型，请检查"` + dbTask.Type + `"`)
	}

	dbTask.Cookie = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(dbTask.Cookie), "Cookie:"), "cookie:")

	return nil
}

func checkAndFormatSpiderTask(dbTask *DBTask) ([]string, error) {
	if len(dbTask.SpiderInfo.Urls) == 0 {
		return nil, errors.New("扫描目标不能为空")
	}

	err := baseCheckAndFormatTask(dbTask)
	if err != nil {
		return nil, err
	}

	for i, domain := range dbTask.SpiderInfo.AllowedDomains {
		domain = strings.TrimSpace(domain)
		dbTask.SpiderInfo.AllowedDomains[i] = domain

		t := targetType(domain)
		if t != "domain" && t != "ip" {
			return nil, errors.New(`爬虫抓取范围必须为域名或者ip，并且不带端口，请检查"` + domain + `"的格式是否为域名或ip`)
		}
	}

	s := set.Set{}
	hostList := []string{}
	for i, urlStr := range dbTask.SpiderInfo.Urls {
		urlStr = strings.TrimSpace(urlStr)
		dbTask.SpiderInfo.Urls[i] = urlStr
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			return nil, errors.New("url必须以http://或https://开头")
		}
		urlObj, err := url.Parse(urlStr)
		if err != nil {
			return nil, err
		}
		hostName := urlObj.Hostname()
		if !s.Has(hostName) {
			hostList = append(hostList, hostName)
			s.Add(hostName)
		}
	}
	s.Clear()

	public, err := IsFilterHostPublic(hostList, dbTask.Hosts)
	if err != nil {
		return nil, err
	}

	// url类型跟扫描队列内外网类型不匹配的
	if (public && strings.Contains(dbTask.Type, "Private")) || (!public && strings.Contains(dbTask.Type, "Public")) {
		info := "外网"
		if !public {
			info = "内网"
		}
		return nil, errors.New(`扫描目标跟所选内外网类型不匹配，请检查网络类型是否为"` + info + `"`)
	}

	return hostList, nil
}
