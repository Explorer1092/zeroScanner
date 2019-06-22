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
	InitDnsCache         = zhttp.SetDnsCache
	paths                = []string{"/phpmyadmin/index.php", "/pma/index.php", "/"}
	usernames, passwords []string
	s                    *zhttp.Session
)

func init() {
	var err error
	usernames, err = util.ReadLines("phpmyadmin_username")
	if err != nil {
		panic(err)
	}
	passwords, err = util.ReadLines("phpmyadmin_password")
	if err != nil {
		panic(err)
	}
}

func Verify(params engine.Params) (result engine.Result) {
	s = zhttp.NewSession(nil)
	newPath := util.GetPaths(paths, params.ParsedTarget.Path)
	params.ParsedTarget.RawQuery = ""

	for _, path := range newPath {
		params.ParsedTarget.Path = path
		resp, err := s.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
			RequestTimeout:     time.Second * 5,
			DialTimeout:        time.Second * 5,
			Hosts:              params.Hosts,
			InsecureSkipVerify: true,
			DisableRedirect:    true,
		})
		if err != nil {
			result.Stop = 24
			return
		}
		if resp.StatusCode() == 200 && strings.Contains(resp.String(), "phpMyAdmin</title>") {
			resp.Close()
			result.Vul = true
			result.VulUrl = params.ParsedTarget.String()
			result.VulInfo = "phpMyAdmin对外"
			vul, username, password := checkWeakPass(params)
			if vul {
				result.Extend = fmt.Sprintf("[%s][%s]", username, password)
				result.VulInfo = "phpMyAdmin弱口令"
			} else {
				result.Level = engine.VulMiddleLevel
			}
			return
		}
		resp.Close()
	}
	result.Stop = 24
	return
}

func checkWeakPass(params engine.Params) (bool, string, string) {
	for _, username := range usernames {
		for _, password := range passwords {
			resp, err := s.Post(params.ParsedTarget.String(), &zhttp.RequestOptions{
				RequestTimeout:     time.Second * 5,
				DialTimeout:        time.Second * 5,
				Hosts:              params.Hosts,
				InsecureSkipVerify: true,
				Data: map[string]string{
					"pma_username": username,
					"pma_password": password,
				},
			})
			if err != nil {
				return false, "", ""
			}
			if resp.HasHeader("Refresh") {
				resp.Close()
				refreshHeader := resp.GetHeader("Refresh")
				tmp := strings.Split(refreshHeader, ";")
				newUrl := strings.TrimSpace(tmp[len(tmp)-1])
				resp, err = s.Get(newUrl, &zhttp.RequestOptions{
					RequestTimeout:     time.Second * 5,
					DialTimeout:        time.Second * 5,
					Hosts:              params.Hosts,
					InsecureSkipVerify: true,
				})
				if err != nil {
					return false, "", ""
				}
			}
			body := resp.String()
			resp.Close()
			if strings.Contains(body, "server_version") {
				return true, username, password
			}
		}
	}
	return false, "", ""
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://114.67.66.82:999/index.php"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
