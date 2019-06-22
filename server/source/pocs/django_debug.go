/*
host
*/
package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
	ports        = []string{"8000"}
)

func Verify(params engine.Params) (result engine.Result) {
	params.ParsedTarget.Path = "/qazwsxedcrfvtgbyhnujm"
	params.ParsedTarget.RawQuery = ""
	newPorts := util.CheckAndInsert(ports, params.ParsedTarget.Port())
	for _, port := range newPorts {
		params.ParsedTarget.Host = strings.TrimSuffix(net.JoinHostPort(params.ParsedTarget.Hostname(), port), ":")
		resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
			RequestTimeout:     time.Second * 5,
			DialTimeout:        time.Second * 5,
			Hosts:              params.Hosts,
			InsecureSkipVerify: true,
			DisableRedirect:    true,
		})
		if err != nil {
			continue
		}
		body := resp.String()
		resp.Close()
		if strings.Contains(body, "Django settings file") {
			result.Vul = true
			result.VulUrl = params.ParsedTarget.String()
			result.VulInfo = "Django debug模式开启"
			return
		}
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://45.56.107.117"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
