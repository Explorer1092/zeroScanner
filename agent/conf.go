package main

import (
	"errors"
	"flag"
	"time"

	"zeroScannerGo/lib/glog"
	"zeroScannerGo/lib/goworker"
)

type Conf struct {
	workerSettings goworker.WorkerSettings
	agentType      string
	token          string
	serverHost     string
}

func flagParse() (*Conf, *glog.Logger) {
	conf := new(Conf)
	conf.workerSettings = defaultWorkerSettings()

	flag.StringVar(&conf.agentType, "type", "", "agent type")
	flag.StringVar(&conf.token, "token", "", "token")
	flag.StringVar(&conf.serverHost, "server", "127.0.0.1:80", "server host, ip:port")
	flag.IntVar(&conf.workerSettings.Concurrency, "worker", 10, "worker num")

	var logLevel, logFile string
	flag.StringVar(&logLevel, "loglevel", "error", "log level")
	flag.StringVar(&logFile, "logfile", "", "log file")
	flag.Parse()

	logger := GetLogger(logLevel, logFile)

	conf.workerSettings.Poller = conf.workerSettings.Concurrency
	if conf.workerSettings.Poller < 0 {
		conf.workerSettings.Poller = 1
	}
	conf.workerSettings.Connections = conf.workerSettings.Poller / 150

	return conf, logger
}

func defaultWorkerSettings() goworker.WorkerSettings {
	return goworker.WorkerSettings{
		Concurrency:    10,
		Connections:    5,
		Poller:         1,
		UseNumber:      true,
		ExitOnComplete: false,
		Interval:       time.Second * 5,
		IsStrict:       true,
	}
}

func checkConf(conf *Conf) error {
	if conf.agentType == "" {
		return errors.New("agent type must be set")
	}
	if conf.token == "" {
		return errors.New("token must be set")
	}
	return nil
}
