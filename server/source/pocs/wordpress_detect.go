/*
host
*/
package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache   = zhttp.SetDnsCache
	versionPattern = regexp.MustCompile(`(?i)wordpress\s*(\d+\.\d+\.\d+)`)
)

func Verify(params engine.Params) (result engine.Result) {
	params.ParsedTarget.Path = "/"
	params.ParsedTarget.RawQuery = ""

	resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
		RequestTimeout:     time.Second * 5,
		DialTimeout:        time.Second * 5,
		Hosts:              params.Hosts,
		RawCookie:          params.Cookie,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	if resp.StatusCode() == 200 {
		body := resp.String()
		if strings.Contains(body, `content="WordPress`) {
			result.Vul = true
			result.VulUrl = params.ParsedTarget.String()
			version := versionPattern.FindStringSubmatch(body)
			if len(version) > 1 {
				result.Extend = version[1]
				result.VulInfo = version[0]
			}
		}
	}
	resp.Close()

	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://datascience.jd.com/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.Cookie = "pin=test;thor=testthor"

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
