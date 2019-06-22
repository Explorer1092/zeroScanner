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
	InitDnsCache = zhttp.SetDnsCache
	paths        = []string{"/users/sign_in", "/gitlab/users/sign_in", "/git/users/sign_in"}
	whiteList    = []string{"fwd.jd.com", "git-fb.jd.com", "monitor-fb.jd.com", "task-fb.jd.com", "git.jcloudec.com", "git.devops.jdcloud.com", "git.devops.jcloud.com", "106.39.164.60", "211.144.24.125", "111.13.24.73"}
)

func Verify(params engine.Params) (result engine.Result) {
	if util.ContainsStr(whiteList, params.ParsedTarget.Hostname()) {
		return
	}
	newPaths := util.GetPaths(paths, params.ParsedTarget.Path)
	for _, path := range newPaths {
		params.ParsedTarget.Path = path
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

		body := resp.String()
		resp.Close()

		if resp.StatusCode() == 200 && strings.Contains(body, "GitLab</title>") {
			result.Vul = true
			result.VulUrl = params.ParsedTarget.String()
			result.VulInfo = "gitlab对外"
			return
		}
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://git.devops.jcloud.com/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
