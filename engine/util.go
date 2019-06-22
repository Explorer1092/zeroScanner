package engine

import (
	"io/ioutil"
	"log"
	"runtime"
	"time"

	"zeroScannerGo/engine/lib/util"
)

func timeCost(start time.Time, info string) {
	pc, _, _, _ := runtime.Caller(1)
	log.Printf("%s took %s\t%s", runtime.FuncForPC(pc).Name(), time.Since(start), info)
}

func fileHash(filePath string) (string, error) {
	buf, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return util.Md5(buf), nil
}

func fileListFromDir(dirPath string) ([]string, error) {
	var fileList []string
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
