package main

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/set"
	"zeroScannerGo/engine/lib/util"
	"gopkg.in/mgo.v2/bson"
)

var (
	fastjsonF = func(data string) (string, bool) {
		if strings.HasPrefix(data, "{") && strings.HasSuffix(data, "}") {
			return "{}", true
		}
		if strings.HasPrefix(data, "[") && strings.HasSuffix(data, "]") {
			return "[]", true
		}
		return "", false
	}

	xxeF = func(data string) (string, bool) {
		if strings.HasPrefix(data, "<?xml") || strings.HasPrefix(data, "<xml") {
			return `<?xml version="1.0">`, true
		}
		return "", false
	}

	//	s2045F = func(data string) (string, bool) {
	//		return "", true
	//	}

	ValidPostFMap = map[string]func(string) (string, bool){
		"fastjson_rce":        fastjsonF,
		"fastjson_rce_dnslog": fastjsonF,
		"xxe":        xxeF,
		"xstreamRce": xxeF,
		//		"s2_045":     s2045F,
	}
)

type ParsedTarget struct {
	Method      string
	Target      string
	ContentType string
	Data        string
	UrlObj      url.URL
}

type SpiderInfo struct {
	Urls           []string
	SpiderIds      []string  // 爬虫id
	Status         int       // 爬取状态
	StartTime      time.Time //爬虫开始爬取的时间
	AllowedDomains []string  `bson:"allowed_domains" json:"allowed_domains"`
	UrlFetched     bool      `bson:"url_fetched" json:"url_fetched"`   // 是否提取了url
	FetchedUrls    []string  `bson:"fetched_urls" json:"fetched_urls"` // 提取url的结果列表
}

type DBTask struct {
	Id         bson.ObjectId     `bson:"_id"` //任务id
	Type       string            //任务类型，如secPublic，techPrivate，icloud等，跟调度器中的name为同样的值
	Thread     int               //线程数, 默认1
	PocName    []string          //poc名, 默认根据服务和端口匹配相应poc
	Target     []string          //目标列表, 或目标关键字必须得有一个, ip, host, 域名或链接, host为带端口的域名或ip
	Service    []string          //任务服务类型, 如http, ssh等, 默认空, 建议填写
	TargetKey  []string          `bson:"target_key" json:"target_key"` //从资产获取target, 如jd_public_ip, jd_public_domain, 数组可添加多个
	Cookie     string            //任务使用的自定义cookie
	Hosts      map[string]string //任务使用hosts
	Status     int               //状态, 默认0, 开始后即为1-100的进度, 完成后为100, 失败为-1
	CreateTime time.Time         //任务创建时间
	Vul        int               //漏洞数量
	Err        []string
	UserAgent  string     `bson:"user_agent" json:"user_agent"`
	SpiderInfo SpiderInfo `bson:"spider_info" json:"spider_info"`
}

type Task struct {
	Id        string
	Thread    int               //每个网站最大线程数
	Queue     string            //任务放入哪个队列
	Cookie    string            //任务使用的自定义cookie
	UserAgent string            //任务使用UserAgent
	Hosts     map[string]string //任务使用hosts
	TaskIter  sync.Map          // 任务map，key为ip或域名，vaule为迭代器

	UpdateTime  time.Time         //上次更新状态时间
	TimeOut     time.Duration     //任务超时时间（秒）
	TimeOuted   bool              //任务超时标志位
	Stop        bool              //任务停止标志位
	doneCount   int64             //扫描完成计数
	vulCount    int64             //漏洞计数
	TargetIdMap map[string]string //url日志记录去重

	pocIterList []*Iter
	//	StreamHandleFunc func() ([]string, error) //流式读取扫描数据
	urlReader    *ESUrlReader
	methodFilter *set.SetNonTS
	exitChan     chan int

	Count  int //已经添加的任务数
	Total  int //任务总数
	Scaned *set.SetNonTS
}

func (self *Task) DoneCount() int {
	return int(atomic.LoadInt64(&self.doneCount))
}

func (self *Task) VulCount() int {
	return int(atomic.LoadInt64(&self.vulCount))
}

func (self *Task) AddDoneCount(count int) {
	atomic.AddInt64(&self.doneCount, int64(count))
}

func (self *Task) AddVulCount(count int) {
	atomic.AddInt64(&self.vulCount, int64(count))
}

func (self *Task) Percent() int {
	return int(float64(self.doneCount) / float64(self.Total) * 100)
}

func (self *Task) GetTaskItem(hostname string) *TaskItem {
	targetIter, ok := self.TaskIter.Load(hostname)
	if !ok {
		return nil
	}
	count := 0
	for {
		taskItem := targetIter.(*TargetIter).Next()
		if taskItem == nil {
			self.TaskIter.Delete(hostname)
			// 减少host在内存中的任务数量计数
			server.scanCount.AddHostTotal(hostname, self.Id, -count)
			return nil
		}
		self.Count++
		count++
		if self.isUsable(taskItem) {
			// 减少host在内存中的任务数量计数
			server.scanCount.AddHostTotal(hostname, self.Id, -count)
			return taskItem
		} else {
			self.AddDoneCount(1)
		}
	}
}

func (self *Task) IsEmpty() bool {
	c := 0
	self.TaskIter.Range(func(k, v interface{}) bool {
		c++
		return true
	})
	return self.urlReader == nil && c == 0
}

// 增加每个host在内存中的任务数量计数
func (self *Task) Start() {
	self.TaskIter.Range(func(k, v interface{}) bool {
		server.scanCount.AddHostTotal(k.(string), self.Id, v.(*TargetIter).Total)
		//		server.Logger.Debug(k.(string), self.Id, v.(*TargetIter).Total)
		return true
	})
}

func (self *Task) Close() {
	if self.exitChan != nil {
		close(self.exitChan)
	}
	// 删除每个host在内存中的任务数量计数
	server.scanCount.RemoveHostCountByTaskId(self.Id)
	server.scanCount.RemoveHostTotalByTaskId(self.Id)
}

func (self *Task) RunStreamHandle() {
	if self.urlReader != nil {
		self.exitChan = make(chan int)
		var firstQuery = make(chan int)
		var first = true
		var closeFirstQuery = func() {
			if firstQuery != nil {
				close(firstQuery)
				firstQuery = nil
			}
		}
		go func() {
			for {
				if !first {
					closeFirstQuery()
				}
				select {
				case <-self.exitChan:
					self.urlReader = nil
					return
				default:
					first = false
					if countTaskNum(self) < 50000 {
						// 防止数据过大，清空去重数据，会造成少量重复扫描，每条数据16字节，不大于10000000条
						if self.Scaned.Size() > 10000000 {
							self.Scaned.Clear()
						}

						var allUrls []string
						var finished bool
						for len(allUrls) < 5000 {
							index, hostInfo := self.urlReader.GetNextHostInfo()

							// 每次轮数发生变化会重新排序，将轮数最小的放在前面，如果索引为0并且读取轮数大于0，说明读完了
							if index == 0 && hostInfo.RoundCount > 0 {
								finished = true
								break
							}

							// 读取到了最后一个host，重置一下索引，从头开始读
							if hostInfo == nil {
								self.urlReader.Reset()
								continue
							}

							maxScan := server.scanCount.GetHostMax(hostInfo.Host)
							if maxScan == 0 {
								maxScan = MAXSCAN
							}
							if hostInfo.RoundCount > 0 || !(server.scanCount.GetHostTotal(hostInfo.Host) < maxScan*10) {
								continue
							}

							urls, err := self.urlReader.QueryUrl(hostInfo)
							if err != nil {
								server.Logger.Error(err)
								if strings.Contains(err.Error(), "code: 106") {
									taskUpdateErr(self.Id, err.Error())
									self.urlReader = nil
									return
								}
								continue
							}

							allUrls = append(allUrls, urls...)
						}

						self.urlReader.Sort()

						if len(allUrls) > 0 {
							allUrls = filterTarget(allUrls, self.methodFilter)
							// 解析
							parsedTargetList := parseTarget(allUrls)
							// 白名单过滤
							parsedTargetList, err := server.whiteList.removeUrlWhiteList(parsedTargetList)
							if err != nil {
								server.Logger.Error(err)
								continue
							}

							// 根据host分类
							parsedTargetMap := classifyTarget(parsedTargetList)

							// 生成迭代器，并放到task中
							for hostname, targetList := range parsedTargetMap {
								ti := new(TargetIter)
								ti.Init(self.pocIterList, targetList)

								self.Total += ti.Total
								server.scanCount.AddHostTotal(hostname, self.Id, ti.Total)

								if _, ok := self.TaskIter.Load(hostname); !ok {
									self.TaskIter.Store(hostname, ti)
								} else {
									self.TaskIter.Store(hostname+"_"+strconv.Itoa(int(time.Now().UnixNano())), ti)
								}
							}
						}
						if finished {
							self.urlReader = nil
							return
						}
					} else {
						time.Sleep(time.Second)
					}
				}
			}
		}()
		select {
		case <-firstQuery:
			return
		}
	}
}

//func (self *Task) RunStreamHandle() {
//	if self.StreamHandleFunc != nil {
//		var firstQuery = make(chan int)
//		var first = true
//		var closeFirstQuery = func() {
//			if firstQuery != nil {
//				close(firstQuery)
//				firstQuery = nil
//			}
//		}
//		go func() {
//			defer closeFirstQuery()
//			for {
//				if !first {
//					closeFirstQuery()
//				}
//				select {
//				case <-self.exitChan:
//					return
//				default:
//					first = false
//					if countTaskNum(self) < 50000 {
//						// 防止数据过大，清空去重数据，会造成少量重复扫描，每条数据16字节，不大于10000000条
//						if self.Scaned.Size() > 10000000 {
//							self.Scaned.Clear()
//						}
//						// 取新url列表
//						urlList, err := self.StreamHandleFunc()
//						if err != nil {
//							server.Logger.Error(err)
//							if strings.Contains(err.Error(), "code: 106") {
//								taskUpdateErr(self.Id, err.Error())
//								return
//							}
//							continue
//						}
//						// 没错误并且数据为空，说明取完了
//						if len(urlList) == 0 {
//							self.StreamHandleFunc = nil
//							return
//						}

//						// 解析
//						parsedTargetList := parseTarget(urlList)
//						// 白名单过滤
//						parsedTargetList, err = server.whiteList.removeUrlWhiteList(parsedTargetList)
//						if err != nil {
//							server.Logger.Error(err)
//							continue
//						}

//						// 根据host分类
//						parsedTargetMap := classifyTarget(parsedTargetList)

//						// 生成迭代器，并放到task中
//						for hostname, targetList := range parsedTargetMap {
//							ti := new(TargetIter)
//							ti.Init(self.pocIterList, targetList)
//							if _, ok := self.TaskIter.Load(hostname); !ok {
//								self.TaskIter.Store(hostname, ti)
//							} else {
//								self.TaskIter.Store(hostname+"_"+strconv.Itoa(int(time.Now().UnixNano())), ti)
//							}
//							self.Total += ti.Total
//						}

//						//						server.Logger.Debug(self.Total, "len(urlList):", len(urlList), "len(parsedTargetList):", len(parsedTargetList), "len(parsedTargetMap):", len(parsedTargetMap))

//					} else {
//						time.Sleep(time.Second)
//					}
//				}
//			}
//		}()
//		select {
//		case <-firstQuery:
//			return
//		}
//	}
//}

/*
	scheme分三种类型，一种是空，一种是http(s)类型，一种是资产提取的port数据，
	带特殊头部fromsourceport-，如fromsourceport-mysql，fromsourceport-http等

	资产提取的port数据单独处理，若匹配到poc的service，则添加，否则跳过

	其他数据检测scheme
	scheme不为空的，匹配scheme，若匹配到，则添加并继续匹配下一个poc，若未匹配到，
	检测scheme是否是http(s)协议，是的话添加该poc的所有service
	scheme为空的，匹配该poc的所有service，如果带端口，则使用自带的端口，否则，使用service的默认端口
*/
func (self *Task) isUsable(taskItem *TaskItem) bool {
	if taskItem.PocType == engine.TypeUrl {
		if (taskItem.Params.ParsedTarget.Path == "" || taskItem.Params.ParsedTarget.Path == "/") && taskItem.Params.ParsedTarget.RawQuery == "" {
			return false
		}

		if taskItem.Params.Method == "POST" {
			validPostF, ok := ValidPostFMap[taskItem.PocName]
			if !ok {
				return false
			}
			replacedData, ok := validPostF(strings.TrimSpace(taskItem.Params.Data))
			if !ok {
				return false
			}
			//合法的POST数据90%的概率丢掉
			if util.RandInt(0, 9) > 0 {
				return false
			}
			taskItem.Params.ParsedTarget.Fragment = ""
			taskItem.Params.ParsedTarget.RawQuery = ""
			taskItem.Params.Data = replacedData
		}
	}

	//	资产端口数据处理
	if strings.HasPrefix(taskItem.Params.ParsedTarget.Scheme, "fromsourceport-") {
		taskItem.Params.ParsedTarget.Scheme = strings.TrimPrefix(taskItem.Params.ParsedTarget.Scheme, "fromsourceport-")
		if taskItem.Service != taskItem.Params.ParsedTarget.Scheme {
			return false
		}
		// 用户添加带协议数据处理
	} else if taskItem.Params.ParsedTarget.Scheme != "" {
		if taskItem.Service != taskItem.Params.ParsedTarget.Scheme {
			if taskItem.Service == "http" || taskItem.Service == "https" {
				return false
			}
			if taskItem.Params.ParsedTarget.Scheme != "http" && taskItem.Params.ParsedTarget.Scheme != "https" {
				return false
			}
			taskItem.Params.ParsedTarget.Scheme = taskItem.Service
			taskItem.Params.ParsedTarget.Host = taskItem.Params.ParsedTarget.Hostname()
			defaultPort := server.servicePortMap[taskItem.Service]
			if defaultPort != "" {
				taskItem.Params.ParsedTarget.Host += ":" + defaultPort
			}
		}
		// 用户添加空协议数据处理
	} else {
		taskItem.Params.ParsedTarget.Scheme = taskItem.Service
		taskItem.Params.ParsedTarget.Path = "/"
		if taskItem.Params.ParsedTarget.Port() == "" {
			if taskItem.Params.ParsedTarget.Scheme != "http" && taskItem.Params.ParsedTarget.Scheme != "https" {
				defaultPort := server.servicePortMap[taskItem.Params.ParsedTarget.Scheme]
				if defaultPort != "" {
					taskItem.Params.ParsedTarget.Host += ":" + defaultPort
				}
			}
		} else {
			if (taskItem.Params.ParsedTarget.Scheme == "http" && taskItem.Params.ParsedTarget.Port() == "80") ||
				(taskItem.Params.ParsedTarget.Scheme == "https" && taskItem.Params.ParsedTarget.Port() == "443") {
				taskItem.Params.ParsedTarget.Host = taskItem.Params.ParsedTarget.Hostname()
			}
		}
	}

	var hash string
	if taskItem.PocType == engine.TypeHost {
		taskItem.Params.ParsedTarget.Path = "/"
		taskItem.Params.ParsedTarget.RawQuery = ""
		taskItem.Params.ParsedTarget.Fragment = ""
		hash = util.Md5([]byte(taskItem.PocName + taskItem.Params.ParsedTarget.Host + taskItem.Params.Username +
			taskItem.Params.Password + taskItem.Params.Other))[8:24]
	} else {
		hash = util.Md5([]byte(taskItem.PocName + taskItem.Params.Method + taskItem.Params.ParsedTarget.String() +
			taskItem.Params.Data + taskItem.Params.Username + taskItem.Params.Password + taskItem.Params.Other))[8:24]
	}

	if self.Scaned.Has(hash) {
		return false
	}
	self.Scaned.Add(hash)
	return true
}
