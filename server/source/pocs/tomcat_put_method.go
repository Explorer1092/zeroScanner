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
	path         = "/zzzzzzzzzzzzzzzzzzzzzzz.txt/"
	payload      = "jdscanner"
)

func Verify(params engine.Params) (result engine.Result) {
	params.ParsedTarget.Path = path
	params.ParsedTarget.RawQuery = ""
	resp, err := zhttp.Put(params.ParsedTarget.String(), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		Hosts:              params.Hosts,
		RawCookie:          params.Cookie,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
		RawData:            payload,
	})
	if err != nil {
		return
	}
	resp.Close()

	//状态码以2开头
	if resp.StatusCode()/100 == 2 {
		urlStr := strings.TrimSuffix(params.ParsedTarget.String(), "/")
		resp, err := zhttp.Get(urlStr, &zhttp.RequestOptions{
			DialTimeout:        time.Second * 5,
			RequestTimeout:     time.Second * 5,
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
		if body == payload {
			result.Vul = true
			result.VulUrl = urlStr
			result.VulInfo = "tomcat put文件上传"
			return
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
