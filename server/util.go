package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"zeroScannerGo/engine"
	"zeroScannerGo/lib/util"
)

var (
	ipPattern         = regexp.MustCompile(`\A(?:\d{1,3}\.){3}\d{1,3}\z`)
	domainPattern     = regexp.MustCompile(`\A\b[a-zA-Z0-9-]+\b(?:\.\b[a-zA-Z0-9-]+\b)+\z`)
	urlPattern        = regexp.MustCompile(`\Ahttps?://\b[a-zA-Z0-9-]+\b(?:\.\b[a-zA-Z0-9-]+\b)+(?::\d{1,5})?(/|\?)\S+\z`)
	hostPattern       = regexp.MustCompile(`\A\b[a-zA-Z0-9-]+\b(?:\.\b[a-zA-Z0-9-]+\b)+(?::\d{1,5})\z`)
	notHttpUrlPattern = regexp.MustCompile(`\A\b[a-zA-Z-]+\b://\b[a-zA-Z0-9-]+\b(?:\.\b[a-zA-Z0-9-]+\b)+(?::\d{1,5})?/?\z`)
	mobilePattern     = regexp.MustCompile(`(?i)(mobile|phone|tel|phonenumber|telephone|telnumber|telnum)=(1\d{10})\b`)
	emailPattern      = regexp.MustCompile(`[\w\.-]+(@|%40)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+`)
)

func targetType(target string) string {
	if ipPattern.MatchString(target) {
		return "ip"
	} else if domainPattern.MatchString(target) {
		return "domain"
	} else if hostPattern.MatchString(target) {
		return "host"
	} else if urlPattern.MatchString(target) {
		return "url"
	} else if notHttpUrlPattern.MatchString(target) {
		return "sourceUrl"
	}
	return "unknown"
}

func getSelfName() string {
	file, _ := exec.LookPath(os.Args[0])
	absFile, _ := filepath.Abs(file)
	_, fileName := path.Split(strings.Replace(absFile, "\\", "/", -1))
	fileName = strings.TrimSuffix(fileName, path.Ext(fileName))
	return fileName
}

//读取资源文件并打包为zip
func Package(filePath string, fileNames []string) ([]byte, error) {
	var b = new(bytes.Buffer)
	zw := zip.NewWriter(b)
	for _, fileName := range fileNames {
		fw, _ := zw.Create(fileName)
		fileContent, err := ioutil.ReadFile(path.Join(filePath, fileName))
		if err != nil {
			zw.Close()
			return nil, err
		}
		_, err = fw.Write(fileContent)
		if err != nil {
			zw.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func FileHash(filePath string) (string, error) {
	buf, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return util.Md5(buf), nil
}

func mkdirs(dirs ...string) error {
	for _, dir := range dirs {
		err := os.MkdirAll(dir, 0644)
		if err != nil && !os.IsExist(err) {
			return err
		}
	}
	return nil
}

func fileListFromDir(dirPath string) ([]string, error) {
	var fileList = []string{}
	dirList, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}
	for _, item := range dirList {
		if !item.IsDir() {
			fileList = append(fileList, item.Name())
		}
	}
	return fileList, nil
}

func loadSourceMap() (map[string]string, error) {
	sourceMap := map[string]string{}

	sourceList, err := fileListFromDir(engine.SourceDir)
	if err != nil {
		return nil, err
	}

	for _, s := range sourceList {
		hash, err := FileHash(path.Join(engine.SourceDir, s))
		if err != nil {
			return nil, err
		}
		sourceMap[s] = hash
	}

	return sourceMap, nil
}

func contains(inSlice []string, inStr string) bool {
	for _, value := range inSlice {
		if value == inStr {
			return true
		}
	}
	return false
}

func splitSoFile(soFileNmae string) (string, string) {
	t := strings.Split(soFileNmae, "_")
	pocName := strings.Join(t[:len(t)-1], "_")
	hash := strings.TrimSuffix(t[len(t)-1], ".so")
	return pocName, hash
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

//解析ip段生成所有ip,如192.168.1.1/24
func parseCidr(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

//解析target，返回method, target, content-type, data
func parseMethod(target string) (string, string, string, string) {
	tmp := strings.Split(target, "§")
	if len(tmp) >= 4 {
		target := strings.TrimSpace(tmp[1])
		if !(strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")) {
			target = "http://" + target
		}
		return tmp[0], target, tmp[2], strings.Replace(tmp[3], `\"`, `"`, -1)
	} else {
		return "GET", target, "", ""
	}
}

func checkAndParseTarget(target string) (*url.URL, string, error) {
	var (
		targetType   string
		parsedTarget *url.URL
	)
	if ipPattern.MatchString(target) {
		parsedTarget = new(url.URL)
		parsedTarget.Host = target
		parsedTarget.Path = "/"
		targetType = "ip"
	} else if domainPattern.MatchString(target) {
		parsedTarget = new(url.URL)
		parsedTarget.Host = target
		parsedTarget.Path = "/"
		targetType = "domain"
	} else if hostPattern.MatchString(target) {
		parsedTarget = new(url.URL)
		parsedTarget.Host = target
		parsedTarget.Path = "/"
		targetType = "host"
	} else if urlPattern.MatchString(target) {
		var err error
		parsedTarget, err = url.Parse(target)
		if err != nil {
			return nil, "", err
		}
		targetType = "url"
	} else if notHttpUrlPattern.MatchString(target) {
		var err error
		parsedTarget, err = url.Parse(target)
		if err != nil {
			return nil, "", err
		}
		targetType = "sourceUrl"
	} else {
		return nil, "", errors.New("unknown target type: " + target)
	}

	return parsedTarget, targetType, nil
}

func Min(first int, rest ...int) int {
	min := first
	for _, v := range rest {
		if v < min {
			min = v
		}
	}
	return min
}

func parseNampServices(nmapServicesFile string) (map[string]string, map[string]string, error) {
	var (
		portServiceMap = map[string]string{}
		servicePortMap = map[string]string{}
	)
	lines, err := util.ReadLines(path.Join(engine.DictsDir, nmapServicesFile))
	if err != nil {
		return portServiceMap, servicePortMap, err
	}
	for _, line := range lines {
		if line == "" || line[0] == '#' {
			continue
		}
		tmp := strings.SplitN(line, "\t", 3)
		if len(tmp) < 3 {
			continue
		}
		service := tmp[0]
		tmp = strings.SplitN(tmp[1], "/", 2)
		if len(tmp) < 2 {
			continue
		}
		port := tmp[0]
		portServiceMap[port] = service
		if servicePortMap[service] == "" {
			servicePortMap[service] = port
		}
	}
	return portServiceMap, servicePortMap, nil
}

func IsPublicIP(IP net.IP) bool {
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return false
		case ip4[0] == 169 && ip4[1] == 254:
			return false
		default:
			return true
		}
	}
	return false
}
