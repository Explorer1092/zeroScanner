package main

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
	"github.com/tidwall/gjson"
	"gopkg.in/olivere/elastic.v3"
)

type ESUrlReader struct {
	hostInfoList      HostInfoList
	hostInfoMap       map[string]*HostInfo
	hostUrlsMap       map[string]*UrlsIter
	hostInfoIndex     int
	api               string
	authId            string
	esApi             string
	esClient          *elastic.Client
	l                 sync.Mutex
	useRedis          bool
	perReadCount      int
	urlCountThreshold int //es中的url数量阈值，小于该阈值的将被缓存到本地内存中
}

type UrlsIter struct {
	urls  []string
	index int
}

func (ui *UrlsIter) Next() (string, bool) {
	if ui.index > len(ui.urls)-1 {
		ui.index = 0
		return "", false
	}
	u := ui.urls[ui.index]
	ui.index++
	return u, true
}

type HostInfo struct {
	Host       string
	ScrollId   string
	Count      int // 当前读取了多少条，每轮重置一次
	RoundCount int // 扫描了多少轮
	totalCount int // es中一共有多少条
}

type HostInfoList []*HostInfo

func (hil HostInfoList) Len() int { return len(hil) }
func (hil HostInfoList) Less(i, j int) bool {
	return hil[i].RoundCount < hil[j].RoundCount || (hil[i].RoundCount == hil[j].RoundCount && hil[i].Count < hil[j].Count)
}
func (hil HostInfoList) Swap(i, j int) { hil[i], hil[j] = hil[j], hil[i] }

func NewEsUrlReader() *ESUrlReader {
	return &ESUrlReader{
		hostInfoMap:       map[string]*HostInfo{},
		hostUrlsMap:       map[string]*UrlsIter{},
		api:               "http://mx-admin.jd.com/AssetsURLSearchAPI",
		authId:            "jGau654qxf",
		esApi:             "http://192.168.180.73:9099",
		perReadCount:      1000,
		urlCountThreshold: 10000,
	}
}

func (ur *ESUrlReader) initEsClient() error {
	client, err := elastic.NewClient(elastic.SetURL(ur.esApi), elastic.SetSniff(false))
	if err != nil {
		return err
	}
	ur.esClient = client
	return nil
}

func (ur *ESUrlReader) getScrollId(host string) (string, bool) {
	ur.l.Lock()
	hostInfo, ok := ur.hostInfoMap[host]
	ur.l.Unlock()
	if !ok {
		return "", false
	}
	return hostInfo.ScrollId, true
}

func (ur *ESUrlReader) saveHostInfo(host, scrollId string, count int) {
	ur.l.Lock()
	defer ur.l.Unlock()
	hostInfo, ok := ur.hostInfoMap[host]
	if !ok {
		return
	}

	if scrollId != "" {
		// 当scrollid不为空，但是count小于每次需要读取的数量时，说明读完了，重置scrollid，扫描次数+1
		if count < ur.perReadCount {
			//			server.Logger.Debug(host, "read finished", count, "len(scrollId):", len(scrollId))
			// 删除scrollid
			ur.clearScrollId([]string{hostInfo.Host}, []string{hostInfo.ScrollId})

			hostInfo.Count = 0
			hostInfo.RoundCount++
			hostInfo.ScrollId = ""

			// 保存扫描轮数
			//			if ur.useRedis {
			//				setHostRoundCount(hostInfo.Host, hostInfo.RoundCount)
			//			}

			// 当RoundCount发生变化，则重新排序
			//			ur.Sort()
		} else {
			//			server.Logger.Debug(host, "read succed", count, "len(scrollId):", len(scrollId))
			hostInfo.Count += count
			if hostInfo.ScrollId != scrollId {
				hostInfo.ScrollId = scrollId
				// 保存scrollid到redis
				if ur.useRedis {
					setHostScrollId(host, scrollId)
				}
			}
		}
		// scrollid为空说明es出问题了，需要重置scrollid
	} else {
		// 删除scrollid
		//		server.Logger.Debug(host, "read failed")
		ur.clearScrollId([]string{hostInfo.Host}, []string{hostInfo.ScrollId})
		hostInfo.Count = 0
		hostInfo.ScrollId = ""
		//		hostInfo.RoundCount = 100000000
		//		ur.Sort()
	}
}

func (ur *ESUrlReader) GetNextHostInfo() (int, *HostInfo) {
	ur.l.Lock()
	defer ur.l.Unlock()
	if len(ur.hostInfoList) > 0 && ur.hostInfoIndex > -1 {
		hostInfo := ur.hostInfoList[ur.hostInfoIndex]
		index := ur.hostInfoIndex
		if ur.hostInfoIndex < len(ur.hostInfoList)-1 {
			ur.hostInfoIndex++
		} else {
			ur.hostInfoIndex = -1
		}
		return index, hostInfo
	}
	return -1, nil
}

func (ur *ESUrlReader) Reset() {
	ur.hostInfoIndex = 0
}

func (ur *ESUrlReader) AutoRefreshHostList(ttl time.Duration) error {
	err := ur.RefreshHostList()
	if err != nil {
		return err
	}
	err = ur.initHostScrollId()
	if err != nil {
		return err
	}

	ur.useRedis = true

	go func() {
		ticker := time.NewTicker(ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err = ur.RefreshHostList()
				if err != nil {
					server.Logger.Error(err)
				}
				err = ur.initHostScrollId()
				if err != nil {
					server.Logger.Error(err)
				}
			}
		}
	}()
	return nil
}

// 排序可以确保被扫描次数较少的host排在前面，优先被检查是否可以添加扫描
func (ur *ESUrlReader) Sort() {
	sort.Sort(ur.hostInfoList)
	ur.hostInfoIndex = 0
}

func (ur *ESUrlReader) RefreshHostList() error {
	// 获取所有es中的域名列表
	hostList, err := ur.queryHostList()
	if err != nil {
		return err
	}

	ur.l.Lock()
	// 增加列表中没有的
	excludeHostList := []string{}
	for host, docCount := range hostList {
		if domainPattern.MatchString(host) {
			if _, ok := ur.hostInfoMap[host]; !ok {
				ur.hostInfoMap[host] = &HostInfo{Host: host, totalCount: docCount}
			}
			if docCount > ur.urlCountThreshold {
				excludeHostList = append(excludeHostList, host)
			}
		}
	}

	// 缓存所有数据量小与阈值的域名url
	err = ur.cacheHostUrls(excludeHostList)
	if err != nil {
		return err
	}

	// 删除列表中已经删除了的
	hostInfoList := []*HostInfo{}
	delHostList := []string{}
	delScrollIdList := []string{}
	for host, hostInfo := range ur.hostInfoMap {
		if _, ok := hostList[host]; ok {
			// 删除host列表中存在，但缓存中不存在的host
			if hostInfo.totalCount <= ur.urlCountThreshold {
				if _, ok := ur.hostUrlsMap[host]; !ok {
					delete(ur.hostInfoMap, host)
					continue
				}
			}
			hostInfoList = append(hostInfoList, hostInfo)
		} else {
			delete(ur.hostInfoMap, host)
			if hostInfo.ScrollId != "" {
				delHostList = append(delHostList, hostInfo.Host)
				delScrollIdList = append(delScrollIdList, hostInfo.ScrollId)
			}
		}
	}

	ur.hostInfoList = hostInfoList
	ur.Sort()
	ur.l.Unlock()
	ur.clearScrollId(delHostList, delScrollIdList)
	return nil
}

// 从es中将数据量很小的域名url先缓存到内存中
func (ur *ESUrlReader) cacheHostUrls(excludeHostList []string) error {
	server.Logger.Info("cache host start ...")
	scrollId := ""

	//day
	startTime := time.Now().Add(-1*time.Hour*24*30).Unix() * 1000
	endTime := time.Now().Unix() * 1000
	queryStr := "-(http_host:" + strings.Join(excludeHostList, " OR http_host:") + ")"

	timeQuery := elastic.NewBoolQuery().Must(elastic.NewRangeQuery("@timestamp").From(startTime).To(endTime)).
		Must(elastic.NewQueryStringQuery(queryStr))

	hostUrlsMap := map[string]*UrlsIter{}
	for {
		searchResult, err := ur.esClient.Scroll().Index("assets-url*").Query(timeQuery).Size(5000).ScrollId(scrollId).Do()
		if err != nil {
			// 读完了
			if err == elastic.EOS {
				break
			}
			return err
		}

		scrollId = searchResult.ScrollId

		for _, hit := range searchResult.Hits.Hits {
			host := gjson.GetBytes(*hit.Source, "http_host").String()
			method := gjson.GetBytes(*hit.Source, "http_method").String()
			url := gjson.GetBytes(*hit.Source, "http_url").String()
			contentType := gjson.GetBytes(*hit.Source, "http_req_content_type").String()
			body := gjson.GetBytes(*hit.Source, "http_req_body").String()
			// 过滤掉数据异常的流量
			if len(url) > 1000 || len(host) > 200 || len(contentType) > 200 || len(body) > 5242880 {
				continue
			}
			if method != "" && url != "" {
				// 过滤掉畸形域名
				if domainPattern.MatchString(host) {
					if _, ok := hostUrlsMap[host]; !ok {
						hostUrlsMap[host] = &UrlsIter{}
					}
					hostUrlsMap[host].urls = append(hostUrlsMap[host].urls, method+"§"+url+"§"+contentType+"§"+body)
				}
			}
		}
	}
	ur.hostUrlsMap = hostUrlsMap

	server.Logger.Info("cache host count:", len(ur.hostUrlsMap))

	return nil
}

func (ur *ESUrlReader) initHostScrollId() error {
	hostScrollId, err := getHostScrollId()
	if err != nil {
		return err
	}

	delList := []string{}

	ur.l.Lock()
	for host, scrollId := range hostScrollId {
		hostInfo, ok := ur.hostInfoMap[host]
		if ok {
			hostInfo.ScrollId = scrollId
		} else {
			delList = append(delList, host)
		}
	}
	ur.l.Unlock()

	delHostScrollId(delList...)
	delHostRollCount(delList...)
	return nil
}

func (ur *ESUrlReader) queryHostList() (map[string]int, error) {
	if ur.esClient == nil {
		err := ur.initEsClient()
		if err != nil {
			return nil, err
		}
	}
	//day
	startTime := time.Now().Add(-1*time.Hour*24*30).Unix() * 1000
	endTime := time.Now().Unix() * 1000

	timeQuery := elastic.NewBoolQuery().Must(elastic.NewRangeQuery("@timestamp").From(startTime).To(endTime)).
		Must(elastic.NewQueryStringQuery(" * "))
	termsAgg := elastic.NewTermsAggregation().Size(9999999).Field("http_host")

	filterAgg := elastic.NewFilterAggregation()
	filterAgg.SubAggregation("1", termsAgg)
	filterAgg.Filter(timeQuery)

	searchResult, err := ur.esClient.Search().Index("assets-url*").Aggregation("0", filterAgg).Do()
	if err != nil {
		return nil, err
	}

	f, _ := searchResult.Aggregations.Filter("0")
	t, _ := f.Aggregations.Terms("1")

	hostList := map[string]int{}
	for _, bucket := range t.Buckets {
		hostList[bucket.Key.(string)] = int(bucket.DocCount)
	}

	return hostList, nil
}

func (ur *ESUrlReader) clearScrollId(hostList []string, scrollIdList []string) {
	if ur.useRedis {
		if len(hostList) > 0 {
			delHostScrollId(hostList...)
		}
	}
	if len(scrollIdList) > 0 {
		ur.esClient.ClearScroll(scrollIdList...).Do()
	}
}

func (ur *ESUrlReader) QueryUrl(hostInfo *HostInfo) ([]string, error) {
	if hostInfo.totalCount <= ur.urlCountThreshold {
		ur.l.Lock()
		allUrls := []string{}
		iter, ok := ur.hostUrlsMap[hostInfo.Host]
		if ok {
			for i := 0; i < ur.perReadCount; i++ {
				u, ok := iter.Next()
				if !ok {
					hostInfo.RoundCount++
					hostInfo.Count = 0
					//					if ur.useRedis {
					//						setHostRoundCount(hostInfo.Host, hostInfo.RoundCount)
					//					}
					break
				}
				allUrls = append(allUrls, u)
				hostInfo.Count++
			}
		}
		ur.l.Unlock()
		return allUrls, nil
	} else {
		return ur.queryUrl(hostInfo.Host)
	}
}

func (ur *ESUrlReader) queryUrl(host string) ([]string, error) {
	scrollId, ok := ur.getScrollId(host)
	if !ok {
		return nil, nil
	}

	timestamp := strconv.Itoa(int(time.Now().Unix()))
	data := map[string]interface{}{
		"authid":            ur.authId,
		"timestamp":         timestamp,
		"sign":              util.Md5([]byte(timestamp + ur.authId)),
		"start_time":        time.Now().Add(time.Hour*24*-600).Unix() * 1000,
		"end_time":          time.Now().Unix() * 1000,
		"count":             ur.perReadCount,
		"guoquan_scanner":   1,
		"scroll_id":         scrollId,
		"scroll_id_timeout": "10080m",
		"host":              host,
	}
	jsonStr, _ := json.Marshal(data)
	resp, err := zhttp.Post(ur.api, &zhttp.RequestOptions{
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
			if code == 106 {
				// 所有节点都失效了才判定为scrollId失效了
				if strings.Contains(errMsg, "Error 404 (Not Found): all shards failed") {
					ur.saveHostInfo(host, "", 0)
				}
			}
			return nil, errors.New("host: " + host + " code: " + strconv.Itoa(int(code)) + " msg: " + errMsg + "scrollId: " + scrollId)
		}

		data := gjson.GetBytes(body, "data").Array()
		for _, item := range data {
			target := item.Get("origin_msg").String()
			if target != "" {
				fetchedUrls = append(fetchedUrls, target)
			}
		}

		if len(data) > 0 {
			scrollId = gjson.GetBytes(body, "scroll_id").String()
			ur.saveHostInfo(host, scrollId, len(data))
		} else {
			ur.saveHostInfo(host, scrollId, 0)
		}
		return fetchedUrls, nil
	}
	server.Logger.Error("host:", host, "statusCode:", resp.StatusCode(), "body:", string(body))
	return nil, errors.New("can't find status code from response body")
}
