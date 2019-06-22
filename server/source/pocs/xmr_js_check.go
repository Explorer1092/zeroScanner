/*
url
*/
package main

import (
	"fmt"
	"net/url"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
	keywords     = []string{"coin-hive", "cryptonight", "coinhive", "hashesPerSecond", "site.key"}
)

func Verify(params engine.Params) (result engine.Result) {
	resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
		RequestTimeout:     time.Second * 5,
		DialTimeout:        time.Second * 5,
		RawCookie:          params.Cookie,
		Hosts:              params.Hosts,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	if resp.StatusCode() == 200 {
		keyword, ok := util.CheckKeyword(keywords, resp.String())
		if ok {
			result.Vul = true
			result.VulUrl = params.ParsedTarget.String()
			result.VulInfo = "门罗币挖矿脚本嵌入"
			result.Extend = "命中关键字: " + keyword
		}
	}
	resp.Close()
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://git.devops.jcloud.com"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
