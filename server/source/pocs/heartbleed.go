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
	resolver *dnscache.Resolver
)

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
		port = "443"
	}

	stdout, _, err := util.Exec("python ./source/heartbleed.py "+ip+" "+port+" 2>&1", time.Second*5)
	if err != nil {
		return
	}
	if strings.Contains(stdout, "vulnerable!") {
		result.Vul = true
		result.VulUrl = ip + ":" + port
		result.VulInfo = "心脏滴血"
	}
	return
}

func main() {
	InitDnsCache(dnscache.New(time.Second * 10))
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://114.67.69.160/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
