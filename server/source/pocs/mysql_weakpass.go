/*
host
*/
package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/lib/dnscache"
)

var (
	resolver             *dnscache.Resolver
	usernames, passwords []string
)

func init() {
	var err error
	usernames, err = util.ReadLines("mysql_username")
	if err != nil {
		panic(err)
	}
	passwords, err = util.ReadLines("mysql_password")
	if err != nil {
		panic(err)
	}
}

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
		port = "3306"
	}
	params.ParsedTarget.Host = host + ":" + port

	for _, username := range usernames {
		for _, password := range passwords {
			db, _ := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/?timeout=3s&readTimeout=3s&writeTimeout=3s", username, password, params.ParsedTarget.Host))
			err = db.Ping()
			db.Close()
			if err != nil {
				if strings.Contains(err.Error(), "Access denied for user") {
					if util.IsPublic(host) {
						result.Vul = true
						result.VulUrl = params.ParsedTarget.Host
						result.VulInfo = "MySQL对外"
						result.Level = engine.VulMiddleLevel
					}
				} else {
					if mysqlClosed(err.Error()) {
						result.Stop = 24
					} //else {
					//		result.Err = err.Error()
					//	}
					return
				}
			} else {
				result.Vul = true
				result.VulUrl = params.ParsedTarget.Host
				result.Extend = fmt.Sprintf("[%s][%s]", username, password)
				result.VulInfo = "MySQL弱口令"
				return
			}
		}
	}
	return
}

func mysqlClosed(text string) bool {
	return strings.Contains(text, "i/o timeout") ||
		strings.Contains(text, "not allowed to connect to") ||
		strings.Contains(text, "No connection could be made") ||
		strings.Contains(text, "no route to host") ||
		strings.Contains(text, "connection refused") ||
		strings.Contains(text, "bad connection")
}

func main() {
	InitDnsCache(dnscache.New(time.Hour * 36))
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://localhost/"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
