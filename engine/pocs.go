package engine

import (
	"errors"
	"net/url"
	"os"
	"path"
	"plugin"
	"strings"
	"sync"
	"time"

	"zeroScannerGo/lib/dnscache"
)

const (
	TypeAll  = "0"
	TypeHost = "1"
	TypeUrl  = "2"
)

type Params struct {
	Method       string  `json:"method"`
	Target       string  `json:"target"`
	ParsedTarget url.URL `json:"parsed_target"`
	Cookie       string  `json:"cookie"`
	Hosts        string  `json:"hosts"`
	UserAgent    string  `json:"user_agent"`
	Data         string  `json:"data"`
	Username     string  `json:"username"`
	Password     string  `json:"password"`
	Other        string  `json:"other"`
	ContentType  string  `json:"content_type"`
	TargetId     string  `json:"target_id"`
}

type Result struct {
	TaskId     string      `json:"taskid"`
	TaskType   string      `json:"tasktype"`
	PocName    string      `json:"pocname"`
	PocType    string      `json:"poc_type"`
	Level      string      `json:"level"`
	Vul        bool        `json:"vul"`
	VulUrl     string      `json:"vul_url"`
	VulInfo    string      `json:"vul_info"`
	Extend     interface{} `json:"extend"`
	Params     Params      `json:"params"`
	RawReq     string      `json:"raw_req"`
	Suggestion string      `json:"suggestion"`
	Stop       int         `json:"stop"`
	Log        bool        `json:"log"`
	Err        string      `json:"err"`
	Host       string      `json:"host"`
	HostType   string      `json:"host_type"`
	Time       time.Time   `json:"time"`
}

type Poc struct {
	Id           string                     `json:"id"`
	Name         string                     `json:"name"`
	Type         string                     `json:"type"` //poc类型 "0": all, "1": host, "2": url
	Code         string                     `json:"code"`
	Info         string                     `json:"info"`
	Service      string                     `json:"service"` //poc支持的服务，以英文逗号分隔，分隔不要带空格
	Services     []string                   `json:"-"`       //解析后的service
	Level        string                     `json:"level"`   //poc严重级别，0:未设置 1:低危 2:中危 3:高危 4:严重
	UsernameDict string                     `json:"username_dict"`
	PasswordDict string                     `json:"password_dict"`
	OtherDict    string                     `json:"other_dict"`
	Suggestion   string                     `json:"suggestion"` //修复方案
	Hash         string                     `json:"hash"`
	UpdateTime   time.Time                  `json:"updatetime"`
	Verify       func(params Params) Result `json:"-"`
}

type pocs struct {
	m      sync.RWMutex
	pocMap map[string]Poc
}

func (self *pocs) Get(pocName string) (Poc, error) {
	self.m.RLock()
	poc, ok := self.pocMap[pocName]
	self.m.RUnlock()
	if !ok {
		return poc, errors.New("unknown poc " + pocName)
	}
	return poc, nil
}

func (self *pocs) makeSoFileName(pocName, pocHash string) string {
	return pocName + "_" + pocHash + ".so"
}

func (self *pocs) getPocName(soFileNmae string) string {
	t := strings.Split(soFileNmae, "_")
	pocName := strings.Join(t[:len(t)-1], "_")
	return pocName
}

func (self *pocs) Update(pocMap map[string]Poc, getCookie func(string) string, dnsCache *dnscache.Resolver) error {
	//加载新poc
	for _, poc := range pocMap {
		oldPoc, ok := self.pocMap[poc.Name]
		if !ok || oldPoc.Hash != poc.Hash {
			verify, initCookie, initDnsCache, err := self.loadPoc(poc.Name, poc.Hash)
			if err != nil {
				return err
			}
			poc.Verify = verify

			if initCookie != nil {
				initCookie(getCookie)
			}
			if initDnsCache != nil {
				initDnsCache(dnsCache)
			}

			pocMap[poc.Name] = poc
		} else {
			poc.Verify = oldPoc.Verify
			pocMap[poc.Name] = poc
		}
	}

	self.RemoveOldSoFiles(pocMap)

	self.m.Lock()
	self.pocMap = pocMap
	self.m.Unlock()
	return nil
}

//func (self *pocs) Update(pocMap map[string]Poc, getCookie func(string) string, dnsCache *dnscache.Resolver) error {
//	//加载新poc
//	for _, poc := range pocMap {
//		verify, initCookie, initDnsCache, err := self.loadPoc(poc.Name, poc.Hash)
//		if err != nil {
//			return err
//		}
//		poc.Verify = verify

//		if initCookie != nil {
//			initCookie(getCookie)
//		}
//		if initDnsCache != nil {
//			initDnsCache(dnsCache)
//		}

//		pocMap[poc.Name] = poc
//	}

//	self.RemoveOldSoFiles(pocMap)

//	self.m.Lock()
//	self.pocMap = pocMap
//	self.m.Unlock()
//	return nil
//}

func (self *pocs) loadPoc(pocName, pocHash string) (func(Params) Result, func(func(string) string), func(*dnscache.Resolver), error) {
	soFile := path.Join(PocsDir, self.makeSoFileName(pocName, pocHash))
	pdll, err := plugin.Open(soFile)
	if err != nil {
		return nil, nil, nil, err
	}
	verifyI, err := pdll.Lookup("Verify")
	if err != nil {
		return nil, nil, nil, err
	}

	verify, ok := verifyI.(func(Params) Result)
	if !ok {
		return nil, nil, nil, errors.New(`Unsupported Verify type`)
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

func (self *pocs) soFileExist(pocName, pocHash string) bool {
	soFile := path.Join(PocsDir, self.makeSoFileName(pocName, pocHash))
	stat, err := os.Stat(soFile)
	if err != nil || stat.IsDir() {
		return false
	}
	return true
}

func (self *pocs) GetNeedDownLoad(pocMap map[string]Poc) []string {
	var needDownLoad []string
	for _, poc := range pocMap {
		if !self.soFileExist(poc.Name, poc.Hash) {
			needDownLoad = append(needDownLoad, poc.Name+"_"+poc.Hash)
		}
	}
	return needDownLoad
}

func (self *pocs) RemoveOldSoFiles(pocMap map[string]Poc) error {
	soFiles, err := fileListFromDir(PocsDir)
	if err != nil {
		return err
	}

	for _, soFileName := range soFiles {
		pocName := self.getPocName(soFileName)
		if poc, ok := pocMap[pocName]; !ok || soFileName != self.makeSoFileName(poc.Name, poc.Hash) {
			os.Remove(path.Join(PocsDir, soFileName))
		}
	}
	return nil
}

func (self *pocs) NeedReboot(pocMap map[string]Poc) bool {
	for _, poc := range pocMap {
		if !self.soFileExist(poc.Name, poc.Hash) {
			return true
		}
	}
	for _, poc := range self.pocMap {
		if _, ok := pocMap[poc.Name]; !ok {
			return true
		}
	}
	return false
}
