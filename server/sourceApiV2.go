package main

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"zeroScannerGo/engine/lib/set"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
	"github.com/tidwall/gjson"
)

type SourceAPI struct {
	_apiMap    map[string]map[string]string
	_paramsMap map[string][]string
}

func (self *SourceAPI) Init(apiMap map[string]map[string]string) {
	self._apiMap = apiMap
	self._paramsMap = map[string][]string{
		"private":   {"is_private", "1"},
		"public":    {"is_private", "2"},
		"cloud":     {"ip_type", "1"},
		"clouduser": {"ip_type", "2"},
		"jd":        {"ip_type", "3"},
		"jr":        {"ip_type", "4"},
		"yhd":       {"ip_type", "5"},
		"it":        {"ip_type", "6"},
		"cdn":       {"ip_type", "7"},
		"other":     {"ip_type", "0"},
	}
}

/*
key的格式
公司_内外网_数据类型:端口
公司_ （可选，支持jd、jr、cloud、clouduser、yhd、it、cdn、other，分别表示京东数据、金融数据、公有云数据、云租户数据、一号店数据、企业it数据、cdn数据、其他）
内外网_ （必需，支持public和private）
数据类型 （必需，支持ip，domain，port、服务关键字，如ssh、端口关键字，如80，其中ip表示提取ip数据，domain表示提取域名数据，port表示提取nmap扫描的端口开放数据，带服务识别结果，服务关键字表示提取运行此类服务的数据，端口关键字表示提取开放此类端口的数据）
:端口 （在数据类型为ip和domain的情况下可用，如果不添加关键字，则提取对应的数据类型，若添加该关键字，则在提取的数据中拼接指定的端口）

示例
jd_public_port
jd_private_22
jd_public_ssh
jd_private_ip
jd_public_domain:2000

public_domain:2000
public_ip:2000
private_redis
private_6379
*/
func (self *SourceAPI) GetSource(keys ...string) ([]map[string]string, error) {
	result := []map[string]string{}
	for _, key := range keys {
		params := map[string]string{}

		var port string
		tmp := strings.Split(key, ":")
		if len(tmp) > 1 {
			key = tmp[0]
			port = tmp[1]
		}

		p := strings.Split(key, "_")
		apiType := p[len(p)-1]
		if _, ok := self._apiMap[apiType]; ok {
			p = p[:len(p)-1]
		}
		for _, x := range p {
			if _, ok := self._paramsMap[x]; !ok {
				apiType = "port"
				if _, err := strconv.Atoi(x); err != nil {
					params["service"] = x
				} else {
					params["port"] = x
				}
				continue
			}
			params[self._paramsMap[x][0]] = self._paramsMap[x][1]
		}
		data, err := self._getSource(apiType, params, port)
		if err != nil {
			return nil, err
		}
		result = append(result, data...)
	}
	return result, nil
}

func (self *SourceAPI) _getSource(apiType string, params map[string]string, port string) ([]map[string]string, error) {
	result := []map[string]string{}
	known := set.New()
	defer known.Clear()

	api := self._apiMap[apiType]
	if api != nil {
		pageNum := 1
		for {
			params["timestamp"] = strconv.Itoa(int(time.Now().Unix()))
			params["auth_id"] = api["auth_id"]
			params["sign"] = util.Md5([]byte(params["timestamp"] + api["auth_id"] + api["auth_key"]))
			params["pageNum"] = strconv.Itoa(pageNum)

			resp, err := zhttp.Get(api["url"], &zhttp.RequestOptions{
				DialTimeout:    time.Second * 5,
				RequestTimeout: time.Minute * 10,
				Params:         params,
			})
			if err != nil {
				return nil, err
			}

			jsonByte := resp.Byte()
			resp.Close()

			statusCode := gjson.GetBytes(jsonByte, "statusCode").Int()
			if statusCode != 1 {
				if !gjson.GetBytes(jsonByte, "statusCode").Exists() {
					return nil, errors.New("key statusCode not exist")
				}
				break
			}

			gjson.GetBytes(jsonByte, "data").ForEach(func(key, value gjson.Result) bool {
				item := map[string]string{}
				value.ForEach(func(k, v gjson.Result) bool {
					if k.Str == "domain" && (apiType == "ip" || apiType == "port") {
						return true
					}

					// jd_public_80 类似这种取特定端口的数据，去掉返回值中的service字段，在下一步处理的时候防止抓到service被当成是jd_public_port类型的数据
					if _, ok := params["port"]; ok && k.Str == "service" {
						return true
					}
					item[k.Str] = v.String()
					return true
				})

				if port != "" && (apiType == "ip" || apiType == "domain") {
					item["port"] = port
				}

				if !known.Has(item["ip"] + item["domain"] + item["port"]) {
					result = append(result, item)
					known.Add(item["ip"] + item["domain"] + item["port"])
				}
				return true
			})
			pageNum++
		}
	}
	return result, nil
}
