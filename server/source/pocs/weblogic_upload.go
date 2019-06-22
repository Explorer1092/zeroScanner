package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache //为zhttp设置dns缓存，引擎会在外部调用InitDnsCache方法
	paths        = []string{
		"/ws_utc/begin.do",
		"/ws_utc/config.do",
	}
)

func Verify(params engine.Params) (result engine.Result) {
	for _, p := range paths {
		params.ParsedTarget.Path = p

		resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
			DialTimeout:     time.Second * time.Second * 5,
			RequestTimeout:  time.Second * 10,
			Hosts:           params.Hosts,
			DisableRedirect: true,
		})
		if err != nil {
			return
		}

		if resp.StatusCode() == 200 {
			if strings.Contains(resp.String(), "title_remove_previous_wsdl") {
				result.Vul = true
				result.VulInfo = "WebLogic 任意文件上传"
				result.Extend = "WebLogic管理页面未授权访问，可上传任意文件导致命令执行"
				result.VulUrl = params.ParsedTarget.String()
				resp.Close()
				return
			}
		}
		resp.Close()
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://114.67.248.98:8080/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.Cookie = "pin=test;thor=testthor"
	//	engine.InitCookie(func(pin string) string {
	//		return "pin=test;thor=testthor"
	//	})

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
