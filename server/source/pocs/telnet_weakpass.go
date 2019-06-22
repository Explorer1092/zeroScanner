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
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/lib/dnscache"
)

var (
	resolver             *dnscache.Resolver
	usernames, passwords []string
)

func init() {
	var err error
	usernames, err = util.ReadLines("telnet_username")
	if err != nil {
		panic(err)
	}
	passwords, err = util.ReadLines("telnet_password")
	if err != nil {
		panic(err)
	}
}

func InitDnsCache(dnsResolver *dnscache.Resolver) {
	resolver = dnsResolver
}

func Verify(params engine.Params) (result engine.Result) {
	host := params.ParsedTarget.Hostname()
	if params.Hosts != "" {
		host = params.Hosts
	}

	ip, err := resolver.FetchOneString(host)
	if err != nil {
		return
	}
	port := params.ParsedTarget.Port()
	if port == "" {
		port = "23"
	}

	for _, username := range usernames {
		for _, password := range passwords {
			cmd := fmt.Sprintf(`python ./source/telnet_weakpass.py %s %s %s "%s" 2>&1`,
				ip, port, username, strings.Replace(password, "{user}", username, -1))
			stdout, _, err := util.Exec(cmd, time.Second*10)
			if err != nil {
				result.Err = stdout
				result.Extend = cmd
				return
			}
			if strings.Contains(stdout, "vul!") {
				result.Vul = true
				result.VulUrl = ip + ":" + port
				result.VulInfo = "telnet弱口令"
				result.Extend = fmt.Sprintf("[%s][%s]", username, password)
				return
			}
			if (strings.Contains(stdout, "timed out") || strings.Contains(stdout, "Connection refused")) && strings.Contains(stdout, "stop!") {
				result.Stop = 24
				return
			}
		}
	}
	return
}

func main() {
	InitDnsCache(dnscache.New(time.Second * 10))
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://203.156.238.115/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
