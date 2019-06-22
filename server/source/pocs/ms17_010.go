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
	resolver  *dnscache.Resolver
	whitelist = []string{"252", "253", "254", "255", "0"}
)

func InitDnsCache(dnsResolver *dnscache.Resolver) {
	resolver = dnsResolver
}

func Verify(params engine.Params) (result engine.Result) {
	host := params.ParsedTarget.Hostname()
	if params.Hosts != "" {
		host = params.Hosts
	}

	port := params.ParsedTarget.Port()
	if port == "" {
		port = "445"
	}

	ip, err := resolver.FetchOneString(host)
	if err != nil {
		return
	}

	tmp := strings.Split(ip, ".")[3]
	if !util.ContainsStr(whitelist, tmp) {
		stdout, _, err := util.Exec("python ./source/smb_ms17_010.py "+ip+" "+port+" 2>&1", time.Second*10)
		if err != nil {
			result.Err = err.Error()
			result.Extend = stdout
			return
		}
		if strings.Contains(stdout, "VULNERABLE") {
			result.Vul = true
			result.VulUrl = ip + ":" + port
			result.VulInfo = "ms17-010远程命令执行"
		}
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
