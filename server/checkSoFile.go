package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"plugin"
	"runtime/debug"
	"strconv"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/lib/dnscache"
)

type TestResult struct {
	Stdout string
	Stderr string
	Err    string
	Result engine.Result
}

func checkPocInSubProcess(soFile string) error {
	command := fmt.Sprintf(`%s checkPoc %s`, os.Args[0], strconv.Quote(soFile))
	_, stderr, err := util.Exec(command, time.Second*3)
	if err != nil || stderr != "" {
		return errors.New("\n[stderr]\n" + stderr + "\n[err]\n" + err.Error())
	}
	return nil
}

func testPocInSubProcess(soFile string, cookieMap map[string]string, params engine.Params) TestResult {
	cookieMapStr, _ := json.Marshal(cookieMap)
	paramsStr, _ := json.Marshal(params)

	command := fmt.Sprintf(`%s testPoc %s %s %s`,
		os.Args[0],
		strconv.Quote(soFile),
		strconv.Quote(string(cookieMapStr)),
		strconv.Quote(string(paramsStr)),
	)

	testResult := TestResult{}
	result := engine.Result{}
	stdout, stderr, err := util.Exec(command, time.Minute*10)
	testResult.Stdout = string(stdout)
	if err != nil {
		testResult.Stderr = string(stderr)
		testResult.Err = err.Error()
		return testResult
	}

	err = json.Unmarshal([]byte(stderr), &result)
	if err != nil {
		testResult.Stderr = string(stderr)
		testResult.Err = err.Error()
		return testResult
	}
	testResult.Result = result
	return testResult
}

func checkSoFile() {
	soFile := flag.Arg(1)
	_, _, _, err := loadSoFile(soFile)
	if err != nil {
		os.Stderr.WriteString(err.Error())
	}
	os.Exit(0)
}

func testSoFile() {
	soFile := flag.Arg(1)
	cookieMapStr := flag.Arg(2)
	paramsStr := flag.Arg(3)

	var (
		params    = engine.Params{}
		result    = engine.Result{}
		cookieMap = map[string]string{}
	)

	err := json.Unmarshal([]byte(cookieMapStr), &cookieMap)
	if err != nil {
		result.Err = err.Error()
		goto output
	}
	err = json.Unmarshal([]byte(paramsStr), &params)
	if err != nil {
		result.Err = err.Error()
		goto output
	}

	result = runSofile(soFile, cookieMap, params)

output:
	resultStr, _ := json.Marshal(result)
	os.Stderr.Write(resultStr)
	os.Exit(0)
}

func runSofile(soFile string, cookieMap map[string]string, params engine.Params) (result engine.Result) {
	verify, initCookie, initDnsCache, err := loadSoFile(soFile)
	if err != nil {
		result = engine.Result{}
		result.Params = params
		result.Err = err.Error()
		return
	}

	defer func() {
		if r := recover(); r != nil {
			result = engine.Result{}
			result.Err = fmt.Sprintf("%v\r\n\r\n%s", r, debug.Stack())
		}
		result.Params = params
		result.Time = time.Now().Local()
	}()

	if initCookie != nil {
		initCookie(func(name string) string {
			if name == "" {
				name = "default"
			}
			return cookieMap[name]
		})
	}

	if initDnsCache != nil {
		resolver := dnscache.New(10 * time.Second)
		defer resolver.Close()
		initDnsCache(resolver)
	}

	result = verify(params)
	return
}

func loadSoFile(soFile string) (func(engine.Params) engine.Result, func(func(string) string), func(*dnscache.Resolver), error) {
	pdll, err := plugin.Open(soFile)
	if err != nil {
		return nil, nil, nil, err
	}

	verifyI, err := pdll.Lookup("Verify")
	if err != nil {
		return nil, nil, nil, err
	}
	verify, ok := verifyI.(func(engine.Params) engine.Result)
	if !ok {
		return nil, nil, nil, errors.New("Unsupported Verify type")
	}

	var (
		initCookie   func(func(string) string)
		initDnsCache func(*dnscache.Resolver)
	)
	initCookieI, err := pdll.Lookup("InitCookie")
	if err == nil {
		switch v := initCookieI.(type) {
		case func(func(string) string):
			initCookie = v
		case *func(func(string) string):
			initCookie = *v
		}
	}

	initDnsCacheI, err := pdll.Lookup("InitDnsCache")
	if err == nil {
		switch v := initDnsCacheI.(type) {
		case func(*dnscache.Resolver):
			initDnsCache = v
		case *func(*dnscache.Resolver):
			initDnsCache = *v
		}
	}

	return verify, initCookie, initDnsCache, nil
}
