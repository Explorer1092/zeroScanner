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
	ports        = []string{"8080", "8009"}
	paths        = [][]string{
		{"/manager/html", "<title>/manager</title>"},
		{"/host-manager/html", "<title>/host-manager</title>"},
	}
	usernames, passwords []string
)

func init() {
	var err error
	usernames, err = util.ReadLines("tomcat_username")
	if err != nil {
		panic(err)
	}
	passwords, err = util.ReadLines("tomcat_password")
	if err != nil {
		panic(err)
	}
}

func Verify(params engine.Params) (result engine.Result) {
	newPorts := util.CheckAndInsert(ports, params.ParsedTarget.Port())

	params.ParsedTarget.Path = "/"
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
		if resp.StatusCode() == 200 && strings.Contains(resp.String(), "<title>Apache Tomcat") {
			resp.Close()
			result.Vul = true
			result.VulUrl = params.ParsedTarget.String()
			result.VulInfo = "tomcat对外"
			vul, vulUrl, username, password := checkWeakPass(params)
			if vul {
				result.VulUrl = vulUrl
				result.Extend = fmt.Sprintf("[%s][%s]", username, password)
				result.VulInfo = "tomcat弱口令"
			} else {
				// 漏洞降级
				result.Level = engine.VulMiddleLevel
			}
			return
		}
		resp.Close()
	}
	result.Stop = 24
	return
}

func checkWeakPass(params engine.Params) (bool, string, string, string) {
	for _, pathObj := range paths {
		params.ParsedTarget.Path = pathObj[0]
	loop:
		for _, username := range usernames {
			for _, password := range passwords {
				resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
					RequestTimeout:     time.Second * 5,
					DialTimeout:        time.Second * 5,
					Hosts:              params.Hosts,
					InsecureSkipVerify: true,
					DisableRedirect:    true,
					Auth:               []string{username, password},
				})
				if err != nil {
					break loop
				}
				if resp.StatusCode() == 200 && strings.Contains(resp.String(), pathObj[1]) {
					resp.Close()
					return true, params.ParsedTarget.String(), username, password
				}
				resp.Close()
			}
		}
	}
	return false, "", "", ""
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
