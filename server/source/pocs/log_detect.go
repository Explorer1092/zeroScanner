/*
host
*/
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
	InitDnsCache = zhttp.SetDnsCache
	path         = "/log.jsp"
)

func Verify(params engine.Params) (result engine.Result) {
	params.ParsedTarget.Path = path
	params.ParsedTarget.RawQuery = ""
	resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
		RequestTimeout:     time.Second * 5,
		DialTimeout:        time.Second * 5,
		Hosts:              params.Hosts,
		RawCookie:          params.Cookie,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
	})
	if err != nil {
		return
	}
	body := resp.String()
	resp.Close()
	if resp.StatusCode() == 200 && strings.Contains(body, "<title>log</title>") && len(body) > 100 {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.VulInfo = "log页面对外"
	}
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
