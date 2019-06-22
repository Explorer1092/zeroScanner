package main

import (
	"os"

	"zeroScannerGo/lib/glog"
)

func GetLogger(level, file string) *glog.Logger {
	var (
		levelMap = map[string]int{
			"debug": glog.LevelDebug,
			"info":  glog.LevelInfo,
			"warn":  glog.LevelWarn,
			"error": glog.LevelError,
			"panic": glog.LevelPanic,
			"fatal": glog.LevelFatal,
		}
		logger *glog.Logger
	)

	if file != "" {
		f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			logger = glog.New(os.Stdout).SetFlags(glog.Lshortfile | glog.LstdFlags)
			logger.Error(err)
		} else {
			logger = glog.New(f).SetFlags(glog.Lshortfile | glog.LstdFlags)
		}
	} else {
		logger = glog.New(os.Stdout).SetFlags(glog.Lshortfile | glog.LstdFlags)
	}

	if l, ok := levelMap[level]; ok {
		logger.SetLevel(l)
	} else {
		logger.SetLevel(glog.LevelError)
		logger.Errorf(`unsupported log level: %q, default level "error" seted`, level)
	}

	return logger
}
