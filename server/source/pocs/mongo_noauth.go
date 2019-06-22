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
	"zeroScannerGo/lib/dnscache"
	"gopkg.in/mgo.v2"
)

var resolver *dnscache.Resolver

func InitDnsCache(dnsResolver *dnscache.Resolver) {
	resolver = dnsResolver
}

func Verify(params engine.Params) (result engine.Result) {
	host := params.ParsedTarget.Hostname()
	if params.Hosts != "" {
		host = params.Hosts
	}

	var err error
	host, err = resolver.FetchOneString(host)
	if err != nil {
		return
	}

	port := params.ParsedTarget.Port()
	if port == "" {
		port = "27017"
	}

	params.ParsedTarget.Host = host + ":" + port

	session, err := mgo.DialWithInfo(&mgo.DialInfo{
		Addrs:     []string{params.ParsedTarget.Host},
		Direct:    true,
		PoolLimit: 1,
		Timeout:   time.Second * 3,
	})
	if err != nil {
		if mongoClosed(err.Error()) {
			result.Stop = 24
		} else {
			result.Err = err.Error()
		}
		return
	}
	defer session.Close()

	dbnames, err := session.DatabaseNames()
	if err != nil {
		if !strings.Contains(err.Error(), "not authorized") {
			result.Err = err.Error()
		}
		return
	}

	result.Vul = true
	result.VulUrl = params.ParsedTarget.Host
	result.VulInfo = "mongo未授权"
	result.Extend = dbnames
	return
}

func mongoClosed(text string) bool {
	return strings.Contains(text, "no reachable servers")
}

func main() {
	InitDnsCache(dnscache.New(time.Second * 10))
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://127.0.0.1/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
