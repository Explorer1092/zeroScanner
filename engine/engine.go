package engine

import (
	"fmt"
	"os"
	"path"
	"runtime/debug"
	"time"

	"zeroScannerGo/lib/dnscache"
)

const SourceDir = "source/"
const PocsDir = SourceDir + "pocs/"   //存放编译后的poc
const DictsDir = SourceDir + "dicts/" //存放字典

// 漏洞级别
const VulLowLevel = "1"
const VulMiddleLevel = "2"
const VulHighLevel = "3"
const VulCriticalLevel = "4"

type Engine struct {
	pocs     *pocs
	cookies  *cookies
	dnsCache *dnscache.Resolver
}

func New(resolver *dnscache.Resolver) *Engine {
	return &Engine{
		pocs: &pocs{
			pocMap: map[string]Poc{},
		},
		cookies: &cookies{
			cookieMap: map[string]string{},
		},
		dnsCache: resolver,
	}
}

func (self *Engine) NeedReboot(pocMap map[string]Poc) bool {
	return self.pocs.NeedReboot(pocMap)
}

func (self *Engine) UpdateCookies(cookieMap map[string]string) {
	self.cookies.Update(cookieMap)
}

func (self *Engine) UpdatePocs(pocMap map[string]Poc) error {
	return self.pocs.Update(pocMap, self.cookies.Get, self.dnsCache)
}

func (self *Engine) GetPocDownloadList(pocMap map[string]Poc) []string {
	return self.pocs.GetNeedDownLoad(pocMap)
}

func (self *Engine) GetSourceDownloadList(sourceMap map[string]string) []string {
	var needDownLoad []string
	for source, hash := range sourceMap {
		sourceHash, _ := fileHash(path.Join(SourceDir, source))
		if sourceHash != hash {
			needDownLoad = append(needDownLoad, source)
		}
	}
	return needDownLoad
}

func (self *Engine) RemoveOldSource(sourceMap map[string]string) error {
	sourceList, err := fileListFromDir(SourceDir)
	if err != nil {
		return err
	}

	for _, sourceName := range sourceList {
		if _, ok := sourceMap[sourceName]; !ok {
			os.Remove(path.Join(SourceDir, sourceName))
		}
	}
	return nil
}

func (self *Engine) RunPoc(pocName string, params Params) (result Result) {
	poc, err := self.pocs.Get(pocName)
	if err != nil {
		result = Result{}
		result.Err = err.Error()
		result.PocName = pocName
		result.Params = params
		result.Time = time.Now().Local()
		return
	}

	defer func() {
		if p := recover(); p != nil {
			result = Result{}
			result.Err = fmt.Sprintf("%v\n\n%s", p, debug.Stack())
		}
		result.PocName = pocName
		result.PocType = poc.Type
		result.Params = params
		result.Time = time.Now().Local()
		if result.Level == "" || (result.Level != VulLowLevel && result.Level != VulMiddleLevel &&
			result.Level != VulHighLevel && result.Level != VulCriticalLevel) {
			result.Level = poc.Level
		}
		if result.Vul && result.Suggestion == "" {
			result.Suggestion = poc.Suggestion
		}
	}()

	// 设置默认cookie
	if params.Cookie == "" {
		params.Cookie = self.cookies.Get("")
	}

	result = poc.Verify(params)
	return
}
