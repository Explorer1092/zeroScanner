/*
host
*/
package main

import (
	"bytes"
	"fmt"
	"net/url"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/socket"
)

var (
	InitDnsCache = socket.SetDnsCache
	payload      = []byte("*1\r\n$4\r\ninfo\r\n")
	vulInfo      = []byte("redis_version")
)

func Verify(params engine.Params) (result engine.Result) {
	timeout := 5 * time.Second

	host := params.ParsedTarget.Hostname()
	if params.Hosts != "" {
		host = params.Hosts
	}
	port := params.ParsedTarget.Port()
	if port == "" {
		port = "6379"
	}

	s := socket.New("tcp")
	s.SetTimeout(timeout)
	s.SetReadAndWriteTimeout(timeout)

	err := s.Connect(host, port)
	if err != nil {
		return
	}
	defer s.Close()

	_, err = s.Write(payload)
	if err != nil {
		return
	}

	resp, err := s.ReadAtLeast(128)
	if err != nil {
		return
	}

	if bytes.Contains(resp, vulInfo) {
		result.Vul = true
		result.VulUrl = host + ":" + port
		result.VulInfo = "redis未授权"
		result.Extend = string(resp)
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://localhost/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
