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
	stdout, _, err := util.Exec("ntpdc -c monlist "+ip+" 2>&1", time.Second*3)
	if err != nil {
		return
	}
	if strings.Contains(stdout, "remote address") {
		result.Vul = true
		result.VulUrl = ip
		result.VulInfo = "ntp反射放大漏洞"
	}
	return
}

func main() {
	InitDnsCache(dnscache.New(time.Second * 10))
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://voice.jd.com/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
