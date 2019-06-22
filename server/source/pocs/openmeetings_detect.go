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
)

func Verify(params engine.Params) (result engine.Result) {
	params.ParsedTarget.Path = "/"
	resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
		RequestTimeout:     time.Second * 5,
		DialTimeout:        time.Second * 5,
		Hosts:              params.Hosts,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
	})
	if err != nil {
		return
	}
	resp.Close()
	if strings.Contains(strings.ToLower(resp.GetHeader("Location")), "openmeetings") {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.VulInfo = "openmeeting对外"
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
