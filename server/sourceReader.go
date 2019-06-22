package main

import (
	"zeroScannerGo/engine"
)

type SourceReader struct {
	ScanSource bool
	sourceAPI  *SourceAPI
}

func (self *SourceReader) Init(apiMap map[string]map[string]string) {
	self.sourceAPI = new(SourceAPI)
	self.sourceAPI.Init(apiMap)
}

/*
资产提取端口的时候，会根据服务匹配对应的poc做任务分发，若服务为空，或者服务不匹配，则尝试使用端口默认服务匹配，若还匹配不到则跳过
提取ip或者域名的时候，会扫描所有的host类型或者all类型的poc
*/
func (self *SourceReader) Read(keys ...string) ([]string, error) {
	source, err := self.sourceAPI.GetSource(keys...)
	if err != nil {
		return nil, err
	}

	formatedSources, err := formatSource(source)
	if err != nil {
		return nil, err
	}

	return formatedSources, err
}

func formatSource(sourceList []map[string]string) ([]string, error) {
	pocMap, err := loadPoc(nil)
	if err != nil {
		server.Logger.Error(err)
		return nil, err
	}

	servicePocNameMap := loadPocNameMap(pocMap, engine.TypeHost, engine.TypeAll)

	var formatedSources []string
	for _, source := range sourceList {
		// 对domain类型的数据直接添加
		if source["domain"] != "" {
			formatedSources = append(formatedSources, source["domain"])
		} else if source["ip"] != "" {
			// 不带service的数据直接添加
			if _, ok := source["service"]; !ok {
				var target = source["ip"]
				var port = source["port"]
				if port != "" {
					target += ":" + port
				}
				formatedSources = append(formatedSources, target)
			} else {
				_, ok := servicePocNameMap[source["service"]]
				if !ok {
					source["service"] = server.portServiceMap[source["port"]]
				}
				_, ok = servicePocNameMap[source["service"]]
				if !ok {
					continue
				}

				var target = source["ip"]
				// 服务为http且端口为80或者服务为https且端口为443，则不添加端口
				if source["port"] != "" && !(source["service"] == "http" && source["port"] == "80") && !(source["service"] == "https" && source["port"] == "443") {
					target += ":" + source["port"]
				}
				// 为资产端口数据做特殊标记
				formatedSources = append(formatedSources, "fromsourceport-"+source["service"]+"://"+target+"/")
			}
		}
	}
	return formatedSources, nil
}
