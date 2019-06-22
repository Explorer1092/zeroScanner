package main

import (
	"archive/zip"
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"zeroScannerGo/engine"
)

type File struct {
	Name string
	Body []byte
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

func DeCompressZip(body []byte) ([]File, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	var fileList []File
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		body, err := ioutil.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		fileList = append(fileList, File{
			Name: zf.Name,
			Body: body,
		})
	}
	return fileList, nil
}

func getSelfIp() string {
	addrs, _ := net.InterfaceAddrs()
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func sendSignal(pid int, s os.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(s)
}

func restartSelf() error {
	agent.Logger.Info("restarting ...")
	filePath, _ := filepath.Abs(os.Args[0])
	err := syscall.Exec(filePath, os.Args, os.Environ())
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

func map2struct(mapOfPoc map[string]interface{}) engine.Poc {
	updateTime, _ := time.Parse("2006-01-02T15:04:05Z", mapOfPoc["updatetime"].(string))
	poc := engine.Poc{
		Id:           mapOfPoc["id"].(string),
		Name:         mapOfPoc["name"].(string),
		Type:         mapOfPoc["type"].(string),
		Code:         mapOfPoc["code"].(string),
		Info:         mapOfPoc["info"].(string),
		Service:      mapOfPoc["service"].(string),
		Level:        mapOfPoc["level"].(string),
		UsernameDict: mapOfPoc["username_dict"].(string),
		PasswordDict: mapOfPoc["password_dict"].(string),
		OtherDict:    mapOfPoc["other_dict"].(string),
		Suggestion:   mapOfPoc["suggestion"].(string),
		Hash:         mapOfPoc["hash"].(string),
		UpdateTime:   updateTime,
	}
	return poc
}
