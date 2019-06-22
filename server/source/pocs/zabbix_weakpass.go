/*
all
*/
package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache         = zhttp.SetDnsCache
	paths                = []string{"/index.php", "/zabbix/index.php"}
	usernames, passwords []string
	blockP               = regexp.MustCompile(`blocked for (\d+)`)
)

func init() {
	var err error
	usernames, err = util.ReadLines("zabbix_username")
	if err != nil {
		panic(err)
	}
	passwords, err = util.ReadLines("zabbix_password")
	if err != nil {
		panic(err)
	}
}

func Verify(params engine.Params) (result engine.Result) {
	newPaths := util.GetPaths(paths, params.ParsedTarget.Path)

	for _, path := range newPaths {
		params.ParsedTarget.Path = path
	loop:
		for _, password := range passwords {
			for _, username := range usernames {
				resp, err := zhttp.Post(params.ParsedTarget.String(), &zhttp.RequestOptions{
					RequestTimeout:     time.Second * 5,
					DialTimeout:        time.Second * 5,
					Hosts:              params.Hosts,
					InsecureSkipVerify: true,
					DisableRedirect:    true,
					ContentType:        "application/x-www-form-urlencoded",
					RawData:            "autologin=1&enter=Sign+in&name=" + username + "&password=" + password + "&request=&sid=test",
				})
				if err != nil {
					result.Stop = 24
					return
				}
				body := resp.String()
				resp.Close()

				if resp.StatusCode() == 200 && strings.Contains(body, "Zabbix</title>") {
					result.Vul = true
					result.VulUrl = params.ParsedTarget.String()
					result.VulInfo = "zabbix对外"
					if strings.Contains(body, "Account is blocked") {
						m := blockP.FindAllStringSubmatch(body, 1)
						if len(m) > 0 {
							s, _ := strconv.Atoi(m[0][1])
							if s > 0 && s < 50 {
								time.Sleep(time.Duration(s) * time.Second)
							}
						}
					}
				} else if resp.StatusCode() == 302 && resp.HasCookie("zbx_sessionid") {
					result.Vul = true
					result.VulUrl = params.ParsedTarget.String()
					result.Extend = fmt.Sprintf("[%s][%s]", username, password)
					result.VulInfo = "zabbix弱口令"
					return
				} else {
					break loop
				}
			}
		}
	}
	result.Stop = 24
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://138.201.106.89/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
