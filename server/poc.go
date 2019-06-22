package main

import (
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/set"
	"zeroScannerGo/lib/util"
)

func loadPocService() ([]string, error) {
	var serviceList = []string{}
	pocs, err := server.pocDb.QueryAllEnable()
	if err != nil {
		return nil, err
	}
	s := set.NewNonTS()
	for _, poc := range pocs {
		services := strings.Split(poc["service"].(string), ",")
		for _, service := range services {
			service = strings.TrimSpace(service)
			if !s.Has(service) {
				serviceList = append(serviceList, service)
				s.Add(service)
			}
		}
	}
	s.Clear()
	return serviceList, nil
}

func loadPocNames(schedulerName string) ([]string, error) {
	var (
		pocNames     = []string{}
		disabledPocs *set.Set
		pocs         []map[string]interface{}
		err          error
	)
	if schedulerName == "" {
		pocs, err = server.pocDb.QueryAll()
		if err != nil {
			return nil, err
		}
		disabledPocs = set.New()
	} else {
		schedulerArgs := server.schedulerManager.GetSchedulerArgs(schedulerName)
		if schedulerArgs == nil {
			return nil, errors.New("unknown type " + schedulerName)
		}
		disabledPocs = schedulerArgs.DisabledPocs
		pocs, err = server.pocDb.QueryAllEnable()
		if err != nil {
			return nil, err
		}
	}
	for _, poc := range pocs {
		if !disabledPocs.Has(poc["name"].(string)) {
			pocNames = append(pocNames, poc["name"].(string))
		}
	}
	return pocNames, nil
}

func loadPoc(disabledPocs *set.Set) (map[string]engine.Poc, error) {
	var pocMap = map[string]engine.Poc{}
	r, err := server.pocDb.QueryAllEnable()
	if err != nil {
		return nil, err
	}

	for _, p := range r {
		poc := engine.Poc{
			Id:           strconv.Itoa(int(p["id"].(int64))),
			Name:         p["name"].(string),
			Type:         p["type"].(string),
			Code:         p["code"].(string),
			Info:         p["info"].(string),
			Service:      p["service"].(string),
			Level:        strconv.Itoa(int(p["level"].(int64))),
			UsernameDict: p["username_dict"].(string),
			PasswordDict: p["password_dict"].(string),
			OtherDict:    p["other_dict"].(string),
			Suggestion:   p["suggestion"].(string),
			Hash:         p["hash"].(string),
			UpdateTime:   p["updatetime"].(time.Time),
		}

		if disabledPocs != nil {
			if disabledPocs.Has(poc.Name) {
				continue
			}
		}

		services := strings.Split(poc.Service, ",")
		for i, service := range services {
			services[i] = strings.TrimSpace(service)
		}
		poc.Services = services

		if !soFileExist(poc.Name, poc.Hash) {
			_, err := compilePoc(poc.Name, poc.Code, poc.Hash)
			if err != nil {
				return nil, err
			}
			server.Logger.Info("compiled", poc.Name, poc.Hash)
		}
		pocMap[poc.Name] = poc
	}
	return pocMap, nil
}

func filterPocMapByPocNames(pocMap map[string]engine.Poc, pocNames []string) map[string][]engine.Poc {
	var r = map[string][]engine.Poc{}
	for _, poc := range pocMap {
		if contains(pocNames, poc.Name) {
			if r[poc.Type] == nil {
				r[poc.Type] = []engine.Poc{poc}
			} else {
				r[poc.Type] = append(r[poc.Type], poc)
			}
		}
	}
	return r
}

func filterPocMapByServices(pocMap map[string]engine.Poc, services []string) map[string][]engine.Poc {
	var r = map[string][]engine.Poc{}
	for _, poc := range pocMap {
		for _, service := range poc.Services {
			if contains(services, service) {
				if r[poc.Type] == nil {
					r[poc.Type] = []engine.Poc{poc}
				} else {
					r[poc.Type] = append(r[poc.Type], poc)
				}
				break
			}
		}
	}
	return r
}

func filterPocMapAll(pocMap map[string]engine.Poc) map[string][]engine.Poc {
	var r = map[string][]engine.Poc{}
	for _, poc := range pocMap {
		if r[poc.Type] == nil {
			r[poc.Type] = []engine.Poc{}
		}
		r[poc.Type] = append(r[poc.Type], poc)
	}
	return r
}

func loadPocNameMap(pocMap map[string]engine.Poc, pocTypes ...string) map[string][]string {
	var r = map[string][]string{}
	for _, poc := range pocMap {
		if contains(pocTypes, poc.Type) {
			for _, service := range poc.Services {
				if r[service] != nil {
					r[service] = append(r[service], poc.Name)
				} else {
					r[service] = []string{poc.Name}
				}
			}
		}
	}
	return r
}

// 加载所有支持host扫描的poc的所有service及对应端口
func loadHostPocService(pocMap map[string]engine.Poc) map[string]string {
	var services = map[string]string{}
	for _, poc := range pocMap {
		if poc.Type == engine.TypeHost || poc.Type == engine.TypeAll {
			for _, service := range poc.Services {
				port := server.servicePortMap[service]
				services[service] = port
			}
		}
	}
	return services
}

func soFileExist(pocName, pocHash string) bool {
	soFile := path.Join(engine.PocsDir, pocName+"_"+pocHash+".so")
	stat, err := os.Stat(soFile)
	if err != nil || stat.IsDir() {
		return false
	}
	return true
}

func compilePoc(pocName, pocCode, pocHash string) (string, error) {
	//生成随机文件名
	randStr := util.RandStr(16, "0123456789abcdefghijklmnopqrstuvwxyz")
	codeFile := path.Join(engine.PocsDir, pocName+"_"+pocHash+"_"+randStr+".go")
	soFile := path.Join(engine.PocsDir, pocName+"_"+pocHash+"_"+randStr+".so")

	//生成go文件
	_, err := util.Write2File(codeFile, pocCode)
	if err != nil {
		return "", err
	}
	defer os.Remove(codeFile)

	//编译go文件
	buildCmd := "go build -buildmode=plugin -o " + soFile + " " + codeFile
	_, stderr, err := util.Exec(buildCmd, time.Minute*5)
	if stderr != "" {
		return "", errors.New(stderr)
	}
	if err != nil {
		return "", err
	}

	//检测插件是否符合标准
	err = checkPocInSubProcess(soFile)
	if err != nil {
		os.Remove(soFile)
		return "", err
	}

	//删除随机字符串，重命名为标准名称
	newSofile := strings.TrimSuffix(soFile, "_"+randStr+".so") + ".so"
	err = os.Rename(soFile, newSofile)
	if err != nil {
		os.Remove(soFile)
		return "", err
	}
	return newSofile, nil
}
