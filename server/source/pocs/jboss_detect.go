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
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
)

func Verify(params engine.Params) (result engine.Result) {
	resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
		RequestTimeout:     time.Second * 5,
		DialTimeout:        time.Second * 5,
		Hosts:              params.Hosts,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	body := resp.String()
	if resp.StatusCode() == 200 && strings.Contains(body, "Welcome to JBoss") {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.VulInfo = "JBoss对外"
		result.Extend = body
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
