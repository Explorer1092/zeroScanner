package main

import (
	"fmt"
	"time"

	"regexp"
	"strings"

	"zeroScannerGo/engine"
	"gopkg.in/redis.v5"
)

//pocname:host:port:path决定扫不扫
//任务分类
//a.URL任务：流量中获取的
//b.DB任务：手动添加你的
//c.资产任务：定时扫描资产
//
//1.触发关键词的不扫，只和URL任务相关，无关POC
//添加URL任务时去重（已做）
//接口：增删查

//2.业务方要求不扫，资产、URL任务均相关，无关POC
//资产扫描时，直接在读取资产后去重（已做）
//URL扫描时，读取URL的时候去重（已做）
//分类：
//整个域名不扫描
//某个接口不扫描（没有某个目录下不扫描）
//接口：host:port增删查
//接口：host:port:path增删查

//3.POC扫描已扫到的(vul)不扫，资产、URL任务和POC均相关：
//任务中的具体业务不扫
//接口：删查。增是在POC中自动添加的

//4.POC设置的白名单不扫，资产、URL任务和POC均相关：：
//任务中的具体业务不扫
//接口：增删查

//5.有些高频请求，没必要重复扫描，一段时间只扫一次即可

//6.已经扫过的 一段时间只扫一次的path

//1和2是一次也不扫，5和6是每个固定时间段内最多扫一次

//poc:host:path
//host = hostname:port

//有一个优化点就是缓存数据，避免和redis频繁交互

type WhiteList struct {
	redisUrl      string
	db            int
	poolSize      int
	client        *redis.Client
	pocNamSp      string         //poc设置的白名单命名空间
	vosNamSp      string         //扫到的漏洞或者stop的白名单命名空间
	ownerHostSet  string         //业务方不允许扫描的域名白名单
	ownerPathSet  string         //业务方不允许扫描的路径白名单
	ownerRgxSet   string         //业务方不允许扫描的路径通配符白名单
	ownerKeySet   string         //业务方不允许扫描的链接中含有关键词的白名单
	keywordSet    string         //触发关键词不扫描的白名单
	scanOnceSet   string         //一段时间只扫一次的path
	scndOnceNamSp string         //已经被扫过的 一段时间只扫一次的path
	hostNameSet   string         //某个host不扫，前缀方式
	logoutSet     string         //退出的关键词
	ipRegexp      *regexp.Regexp // 匹配IP的正则
}

//初始化redis客户端
func (self *WhiteList) init() error {

	self.pocNamSp = "p"
	self.vosNamSp = "v" //vul or stop name space
	self.ownerHostSet = "ownerHost"
	self.ownerPathSet = "ownerPath"
	self.ownerRgxSet = "ownerRgx"
	self.ownerKeySet = "ownerKey"
	self.keywordSet = "keyword"
	self.scanOnceSet = "scanOnce"
	self.scndOnceNamSp = "s"
	self.hostNameSet = "hostName"
	self.logoutSet = "logout"
	self.ipRegexp = regexp.MustCompile(`\A(?:\d{1,3}\.){3}\d{1,3}\z`)

	redisOption, err := redis.ParseURL(self.redisUrl)
	if err != nil {
		return err
	}
	redisOption.DB = self.db
	redisOption.PoolSize = self.poolSize
	self.client = redis.NewClient(redisOption)
	return nil
}

//测试
func (self *WhiteList) test() {
	pong, err := self.client.Ping().Result()
	fmt.Println(pong, err)
}

//关闭redis连接
func (self *WhiteList) close() {
	self.client.Close()
}

//写接口的时候小心删除的坑

//向set添加元素
func (self *WhiteList) addItemToSet(item, set string) error {
	_, err := self.client.SAdd(set, item).Result()
	if err != nil {
		server.Logger.Error(err)
		return err
	}
	return nil
}

//从set删除元素
func (self *WhiteList) delItemFromSet(item, set string) error {
	_, err := self.client.SRem(set, item).Result()
	if err != nil {
		server.Logger.Error(err)
		return err
	}
	return nil
}

//获取set元素集合元素
func (self *WhiteList) getSetItems(set string) ([]string, error) {
	result, err := self.client.SMembers(set).Result()
	if err != nil {
		server.Logger.Error(err)
		return nil, err
	}
	return result, nil
}

//获取set元素集合元素
func (self *WhiteList) getSetLength(set string) (int64, error) {
	result, err := self.client.SCard(set).Result()
	if err != nil {
		server.Logger.Error(err)
		return -1, err
	}
	return result, nil
}

//添加key元素
func (self *WhiteList) addKeyItem(item string, expireHour time.Duration) error {
	_, err := self.client.Set(item, 1, expireHour).Result()
	if err != nil {
		server.Logger.Error(err)
		return err
	}
	return nil
}

//删除key元素
func (self *WhiteList) delKeyItem(item string) error {

	_, err := self.client.Del(item).Result()
	if err != nil {
		server.Logger.Error(err)
		return err
	}
	return nil
}

//获取符合filter的key元素
func (self *WhiteList) getKeyItems(filter string) ([]string, error) {
	result, err := self.client.Keys(filter).Result()
	if err != nil {
		server.Logger.Error(err)
		return nil, err
	}
	return result, nil
}

//8.增。
//在redis中添加不扫描的Logout关键词
func (self *WhiteList) addLogoutItem(item string) error {
	return self.addItemToSet(item, self.logoutSet)
}

//8.删。
//删除zero设置的不扫描的Logout关键词
func (self *WhiteList) delLogoutItem(item string) error {
	return self.delItemFromSet(item, self.logoutSet)
}

//8.查
//获取zero设置的不扫描的Logout关键词
func (self *WhiteList) getLogoutItems() ([]string, error) {
	return self.getSetItems(self.logoutSet)
}

//7.增。
//在redis中添加不扫描的hostname
func (self *WhiteList) addZeroHostItem(item string) error {
	return self.addItemToSet(item, self.hostNameSet)
}

//7.删。
//删除zero设置的不扫描的hostname
func (self *WhiteList) delZeroHostItem(item string) error {
	return self.delItemFromSet(item, self.hostNameSet)
}

//7.查
//获取zero设置的不扫描的hostname
func (self *WhiteList) getZeroHostItems() ([]string, error) {
	return self.getSetItems(self.hostNameSet)
}

//6.增。
//在redis中添加已经被扫过的8h只扫一次的path的白名单
func (self *WhiteList) addScndOnceItem(host, path string) error {
	return self.addKeyItem(self.scndOnceNamSp+":"+host+":"+path, time.Hour*8)
}

//6.查 尽量不要调用该接口
//获取已经被扫过的8h只扫一次的path的白名单
func (self *WhiteList) getScndOnceItems() ([]string, error) {
	return self.getKeyItems(self.scndOnceNamSp + ":*")
}

//5.增。
//在redis中添加一天只扫一次的path的白名单
func (self *WhiteList) addScanOnceItem(host, path string) error {
	return self.addItemToSet(host+":"+path, self.scanOnceSet)
}

//5.删。
//删除一天只扫一次的path的白名单
//根据设置好的item，删除poc自定义忽略的指定的白名单
func (self *WhiteList) delScanOnceItem(item string) error {
	return self.delItemFromSet(item, self.scanOnceSet)
}

//5.查
//获取一天只扫一次的path的白名单
func (self *WhiteList) getScanOnceItems() ([]string, error) {
	return self.getSetItems(self.scanOnceSet)
}

//4.增。
//根据poc名、poc类型和URL，在redis中添加poc自定义忽略的白名单
func (self *WhiteList) addPocItem(pocname string, host, path string) error {
	return self.addKeyItem(self.pocNamSp+":"+pocname+":"+host+":"+path, 0)
}

//4.删。
//根据设置好的item，删除poc自定义忽略的指定的白名单
func (self *WhiteList) delPocItem(host, path string) error {
	return self.delKeyItem(self.pocNamSp + ":" + host + ":" + path)
}

//4.查 这个接口少调用
//获取poc自定义忽略的白名单列表
func (self *WhiteList) getPocItems(pocname string, filter string) ([]string, error) {
	return self.getKeyItems(self.pocNamSp + ":" + pocname + ":" + filter)
}

//3.增。 自动添加，没有对外接口
//根据poc名、host、path，在redis中添加已扫到有漏洞而忽略的白名单
func (self *WhiteList) addVulOrStopIgnoredItem(pocname, host, path string, expiredHours time.Duration) error {
	return self.addKeyItem(self.vosNamSp+":"+pocname+":"+host+":"+path, expiredHours)
}

//3.删
//根据设置好的host, path，删除已有漏洞而忽略的指定白名单，似乎这个接口不应该存在
func (self *WhiteList) delVulOrStopIgnoredItem(host, path string) error {
	return self.delKeyItem(self.vosNamSp + ":" + host + ":" + path)
}

//3.查 这个接口少调用
//获取有漏洞而忽略的白名单列表
func (self *WhiteList) getVulOrStopIgnoredItems(pocname string, filter string) ([]string, error) {
	return self.getKeyItems(self.vosNamSp + ":" + pocname + ":" + filter)
}

//2.1.增
//添加业务方要求不扫描的host白名单:www.jd.com:80
func (self *WhiteList) addOwnerHostItem(host string) error {
	//有效期永久，需要手动删除才失效
	return self.addItemToSet(host, self.ownerHostSet)
}

//2.1.删
//删除业务方要求不扫描的白名单中的某个host:www.jd.com:80
func (self *WhiteList) delOwnerHostItem(host string) error {
	return self.delItemFromSet(host, self.ownerHostSet)
}

//2.1.查
//获取所有业务方要求不扫描的host白名单列表
func (self *WhiteList) getOwnerHostItems() ([]string, error) {
	return self.getSetItems(self.ownerHostSet)
}

//2.2.增
//添加业务方要求不扫描的path白名单:www.jd.com:80/test
func (self *WhiteList) addOwnerPathItem(host, path string) error {
	//有效期永久，需要手动删除才失效
	return self.addItemToSet(host+":"+path, self.ownerPathSet)
}

//2.2.删
//删除业务方要求不扫描的path白名单的某个path:www.jd.com:80/test
func (self *WhiteList) delOwnerPathItem(item string) error {
	return self.delItemFromSet(item, self.ownerPathSet)
}

//2.2.查
//获取所有业务方要求不扫描的path白名单的列表
func (self *WhiteList) getOwnerPathItems() ([]string, error) {
	return self.getSetItems(self.ownerPathSet)
}

//2.3.增
//添加业务方要求不扫描的path通配符白名单:www.jd.com:80 /test
func (self *WhiteList) addOwnerRgxItem(host, path string) error {
	return self.addItemToSet(host+":"+path, self.ownerRgxSet)
}

//2.3.删
//删除业务方要求不扫描的path通配符白名单的某个path: www.jd.com:80:/test
func (self *WhiteList) delOwnerRgxItem(item string) error {
	return self.delItemFromSet(item, self.ownerRgxSet)
}

//2.3.查 ----用户查看接口
//获取所有业务方要求不扫描的path通配符白名单的列表
func (self *WhiteList) getOwnerRgxItems() ([]string, error) {
	return self.getSetItems(self.ownerRgxSet)

}

//2.3.查 ----程序调用接口
//获取所有业务方要求不扫描的path通配符白名单的列表
func (self *WhiteList) getOwnerRgxMap() (map[string][]string, error) {
	result := map[string][]string{}
	allItems, err := self.getSetItems(self.ownerRgxSet)
	if err != nil {
		return nil, err
	}
	for _, item := range allItems {
		itemArr := strings.Split(item, ":")
		if len(itemArr) == 3 {
			//host中含有冒号分隔符
			key := itemArr[0] + ":" + itemArr[1]
			value := itemArr[2]
			result[key] = append(result[key], value)
		}
	}
	return result, nil
}

//2.4.增
//添加业务方不允许扫描的链接中含有关键词的白名单:www.jd.com:80:token
func (self *WhiteList) addOwnerKeyItem(host, key string) error {
	return self.addItemToSet(host+":"+key, self.ownerKeySet)
}

//2.4.删
//删除业务方不允许扫描的链接中含有关键词的白名单:www.jd.com:80:token
func (self *WhiteList) delOwnerKeyItem(item string) error {
	return self.delItemFromSet(item, self.ownerKeySet)
}

//2.4.查 ----用户查看接口
//获取业务方不允许扫描的链接中含有关键词的白名单的列表
func (self *WhiteList) getOwnerKeyItems() ([]string, error) {
	return self.getSetItems(self.ownerKeySet)

}

//2.4.查 ----程序调用接口
//获取所有业务方不允许扫描的链接中含有关键词的白名单的列表
func (self *WhiteList) getOwnerKeyMap() (map[string][]string, error) {
	result := map[string][]string{}
	allItems, err := self.getSetItems(self.ownerKeySet)
	if err != nil {
		return nil, err
	}
	for _, item := range allItems {
		itemArr := strings.Split(item, ":")
		if len(itemArr) == 3 {
			//host中含有冒号分隔符
			key := itemArr[0] + ":" + itemArr[1]
			value := itemArr[2]
			result[key] = append(result[key], value)
		}
	}
	return result, nil
}

//1.增
//添加keyword到关键词白名单
func (self *WhiteList) addKeywordItem(keyword string) error {
	return self.addItemToSet(keyword, self.keywordSet)
}

//1.删
//删除关键词白名单中的某个keyword
func (self *WhiteList) delKeywordItem(keyword string) error {
	return self.delItemFromSet(keyword, self.keywordSet)
}

//1.查
//获取关键词白名单列表，关键词的匹配不是在数据库中做的，所以取回的时候要把"NamSp:"删除
func (self *WhiteList) getKeywordItems() ([]string, error) {
	return self.getSetItems(self.keywordSet)
}

//标记task中的任务，true代表不在白名单中，false在白名单中
func (self *WhiteList) getScannedTaskItemsInfos(arrayItems []string) ([]bool, error) {
	result := []bool{}
	piResult, err := self.getRedisCmpInfo(self.pocNamSp, arrayItems)
	if err != nil {
		return nil, err
	}
	viResult, err := self.getRedisCmpInfo(self.vosNamSp, arrayItems)
	if err != nil {
		return nil, err
	}
	var piTmpValid, viTmpValid bool
	//len(piResult) == len(viResult)
	for i := 0; i < len(piResult); i++ {
		switch piResult[i].(type) {
		case string:
			piTmpValid = false
		default:
			piTmpValid = true
		}
		switch viResult[i].(type) {
		case string:
			viTmpValid = false
		default:
			viTmpValid = true
		}
		if piTmpValid && viTmpValid {
			result = append(result, true)
		} else {
			result = append(result, false)
		}
	}
	return result, nil
}

//在redis中比对存在信息
func (self *WhiteList) getRedisCmpInfo(nameSpace string, arrayItems []string) ([]interface{}, error) {
	if len(arrayItems) == 0 {
		return []interface{}{}, nil
	}
	newArrayItems := []string{}
	for _, value := range arrayItems {
		newArrayItems = append(newArrayItems, nameSpace+":"+value)
	}
	searchResult, err := self.client.MGet(newArrayItems...).Result()
	if err != nil {
		return nil, err
	}
	return searchResult, nil
}

//根据pocname、target、port、poctype构建一条白名单string
func (self *WhiteList) buildWhitelistItem(pocname, scheme, hostName, port, path, pocType string) string {
	host, path := self.getHostAndPathOfTarget(scheme, hostName, port, path, pocType)
	return pocname + ":" + host + ":" + path
}

//根据urlStr和poctype返回host path+
func (self *WhiteList) getHostAndPathOfTarget(scheme, hostName, port, path, pocType string) (string, string) {
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else if scheme == "https" {
			port = "443"
		}
	}
	if pocType == engine.TypeHost || pocType == engine.TypeAll {
		path = "/"
	} else {
		if path == "" {
			path = "/"
		}
	}

	return hostName + ":" + port, path
}

//给定任务列表，获取删除白名单后要扫描的任务
func (self *WhiteList) filterScannedTask(allTask []*TaskItem) ([]*TaskItem, error) {
	//	server.Logger.Debug("[filterScannedTask]before filter:", len(allTask))
	taskItemList := []*TaskItem{}      //待扫描列表
	scannedQuery := []string{}         //redis查询参数暂存
	for _, taskItem := range allTask { //根据taskItem成查询参数
		scannedQuery = append(scannedQuery, self.buildWhitelistItem(
			taskItem.PocName,
			taskItem.Params.ParsedTarget.Scheme,
			taskItem.Params.ParsedTarget.Hostname(),
			taskItem.Params.ParsedTarget.Port(),
			taskItem.Params.ParsedTarget.Path,
			taskItem.PocType,
		))
	}
	scannedInfo, err := self.getScannedTaskItemsInfos(scannedQuery) //从redis查询，返回查询结果，为true false 列表
	if err != nil {
		return nil, err
	}
	for index, value := range scannedInfo {
		if value {
			taskItemList = append(taskItemList, allTask[index])
		}
	}
	//	server.Logger.Debug("[filterScannedTask]after  filter:", len(taskItemList))
	return taskItemList, nil
}

//redis中的某个set to map
func (self *WhiteList) getSetMap(set string) (map[string]bool, error) {
	ownerHost := map[string]bool{}
	dbOwnerHost, err := self.getSetItems(set)
	if err != nil {
		return nil, err
	}
	for i, max := 0, len(dbOwnerHost); i < max; i++ {
		ownerHost[dbOwnerHost[i]] = true
	}
	return ownerHost, nil
}

func (self *WhiteList) inOwnerRgxPath(ownerRgxMap map[string][]string, host, path string) bool {
	for _, ownerRgxPath := range ownerRgxMap[host] {
		if strings.HasPrefix(path, ownerRgxPath) {
			return true
		}
	}
	return false
}

func (self *WhiteList) hasOwnerKey(ownerKeyMap map[string][]string, host, rawquery, postdata string) bool {
	rawquery = strings.TrimSpace(rawquery)
	postdata = strings.TrimSpace(postdata)
	if rawquery == "" && postdata == "" {
		return false
	}
	for _, ownerKey := range ownerKeyMap[host] {
		pkey := ownerKey + "="
		ckey := "&" + ownerKey + "="
		if strings.HasPrefix(rawquery, pkey) || strings.Contains(rawquery, ckey) || strings.HasPrefix(postdata, pkey) || strings.Contains(postdata, ckey) {
			//			fmt.Println("触发关键词", host, ":", ownerKey, ";rawquery:", rawquery, ";postdata:", postdata)
			return true
		}
	}
	return false
}

//判断是不是扫描器设置的host白名单
func (self *WhiteList) inHostnameSet(hostMap map[string]bool, hostname string) bool {
	if !self.ipRegexp.MatchString(hostname) {
		return hostMap[hostname]
	}
	ipArr := strings.Split(hostname, ".")
	var prefix string
	for i, item := range ipArr {
		prefix += item
		if hostMap[prefix] {
			return true
		}
		if i < len(ipArr)-1 {
			prefix += "."
		}
	}
	return false
}

//删除url中触发业务设置的host或者path白名单的条目
func (self *WhiteList) removeUrlWhiteList(targetList []ParsedTarget) ([]ParsedTarget, error) {
	//	server.Logger.Debug("[removeUrlWhiteList]before filter:", len(targetList))
	ownerHostMap, err := self.getSetMap(self.ownerHostSet)
	if err != nil {
		return nil, err
	}
	ownerPathMap, err := self.getSetMap(self.ownerPathSet)
	if err != nil {
		return nil, err
	}
	zeroHostMap, err := self.getSetMap(self.hostNameSet)
	if err != nil {
		return nil, err
	}
	ownerRgxMap, err := self.getOwnerRgxMap()
	ownerKeyMap, err := self.getOwnerKeyMap()
	result := []ParsedTarget{}
	for _, targetItem := range targetList {
		host, path := self.getHostAndPathOfTarget(targetItem.UrlObj.Scheme, targetItem.UrlObj.Hostname(), targetItem.UrlObj.Port(), targetItem.UrlObj.Path, engine.TypeUrl)
		if !self.inHostnameSet(zeroHostMap, targetItem.UrlObj.Hostname()) &&
			ownerHostMap[host] == false && ownerPathMap[host+":"+path] == false &&
			!self.inOwnerRgxPath(ownerRgxMap, host, path) &&
			!self.hasOwnerKey(ownerKeyMap, host, targetItem.UrlObj.RawQuery, targetItem.Data) {
			result = append(result, targetItem)
		}
	}
	//	server.Logger.Debug("[removeUrlWhiteList]after  filter:", len(result))
	return result, nil
}

//资产数据中，删除也无妨设置的白名单条目
func (self *WhiteList) removeSourceWhiteList(targetList []ParsedTarget) ([]ParsedTarget, error) {
	//	server.Logger.Debug("[removeSourceWhiteList]before filter:", len(targetList))
	result := []ParsedTarget{}
	ownerHostWhitelist, err := self.getSetMap(self.ownerHostSet)
	if err != nil {
		return nil, err
	}
	zeroHostMap, err := self.getSetMap(self.hostNameSet)
	if err != nil {
		return nil, err
	}
	for _, targetItem := range targetList {
		host, _ := self.getHostAndPathOfTarget(targetItem.UrlObj.Scheme, targetItem.UrlObj.Hostname(), targetItem.UrlObj.Port(), targetItem.UrlObj.Path, engine.TypeHost)
		if !self.inHostnameSet(zeroHostMap, targetItem.UrlObj.Hostname()) && ownerHostWhitelist[host] == false {
			result = append(result, targetItem)
		}
	}
	//	server.Logger.Debug("[removeSourceWhiteList]after  filter:", len(result))
	return result, nil
}

//有些链接特定时间内只扫描一次，删除已经扫过的这些链接
func (self *WhiteList) removeScndOnceUrl(targetList []ParsedTarget) ([]ParsedTarget, error) {
	//	server.Logger.Debug("[removeScndOnceUrl]before filter:", len(targetList))
	result := []ParsedTarget{}
	scanOnceList, err := self.getSetItems(self.scanOnceSet)
	if err != nil {
		return nil, err
	}
	scanOnceMap := map[string]bool{}
	for i, max := 0, len(scanOnceList); i < max; i++ {
		scanOnceMap[scanOnceList[i]] = true
	}
	scndOnceList, err := self.getRedisCmpInfo(self.scndOnceNamSp, scanOnceList)
	if err != nil {
		return nil, err
	}
	scndOnceMap := map[string]bool{}
	for i, max := 0, len(scndOnceList); i < max; i++ {
		switch scndOnceList[i].(type) {
		case string:
			scndOnceMap[scanOnceList[i]] = true
		}
	}
	for _, targetObj := range targetList {
		host, path := self.getHostAndPathOfTarget(targetObj.UrlObj.Scheme, targetObj.UrlObj.Hostname(), targetObj.UrlObj.Port(), targetObj.UrlObj.Path, engine.TypeUrl)
		mapKey := host + ":" + path
		if scanOnceMap[mapKey] == false {
			result = append(result, targetObj)
		} else {
			if scndOnceMap[mapKey] == false {
				result = append(result, targetObj)
				self.addScndOnceItem(host, path)
			}
		}
	}
	//	server.Logger.Debug("[removeScndOnceUrl]after  filter:", len(result))
	return result, nil
}
