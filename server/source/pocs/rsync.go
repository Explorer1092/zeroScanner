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

	var command string
	if params.ParsedTarget.Port() != "" {
		command = "rsync --timeout=3 " + ip + " " + params.ParsedTarget.Port() + "::"
	} else {
		command = "rsync --timeout=3 " + ip + "::"
	}

	_, _, err = util.Exec(command, time.Second*5)
	if err != nil {
		return
	} else {
		result.Vul = true
		result.VulInfo = "rsync未授权访问"
		result.VulUrl = strings.TrimRight(ip+":"+params.ParsedTarget.Port(), ":")
		result.Extend = command
	}
	return
}

func main() {
	InitDnsCache(dnscache.New(time.Second * 5))
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "https://111.206.226.11"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.Cookie = "pin=test;thor=testthor"

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
