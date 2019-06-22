package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"zeroScannerGo/lib/glog"
	"zeroScannerGo/lib/goworker"
)

type Conf struct {
	AgentToken     string                       `toml:"agent_token"`
	ApiToken       string                       `toml:"api_token"`
	WorkerNum      int                          `toml:"worker_num"`
	ApiPort        int                          `toml:"api_port"`
	RedisUrl       string                       `toml:"redis_url"`
	MongoUrl       string                       `toml:"mongo_url"`
	DbFile         string                       `toml:"db_file"`
	Log            Log                          `toml:"log"`
	Kafka          Kafka                        `toml:"zookeeper"`
	SourceApi      map[string]map[string]string `toml:"source_api"`
	workerSettings goworker.WorkerSettings
}

type Kafka struct {
	Server string   `toml:"server"`
	Topics []string `toml:"topics"`
}

type Log struct {
	Level string `toml:"level"`
	File  string `toml:"file"`
}

func confParse(tomlFile string) (*Conf, *glog.Logger) {
	conf := defaultConf()
	_, err := toml.DecodeFile(tomlFile, conf)

	//创建默认配置并退出
	if err != nil {
		if os.IsNotExist(err) {
			tomlFile := server.name + ".toml"
			if err := createDefaultTomlFile(tomlFile); err != nil {
				fmt.Println("create configuration file failed, err:", err)
				os.Exit(1)
			} else {
				fmt.Println(`The configuration file "` + tomlFile + `" has been created. Please fill in the basic configuration`)
				os.Exit(0)
			}
		}
		fmt.Println(err)
		os.Exit(1)
	}

	conf.workerSettings = defaultWorkerSettings()
	conf.workerSettings.URI = conf.RedisUrl
	conf.workerSettings.Concurrency = conf.WorkerNum
	conf.workerSettings.Poller = conf.workerSettings.Concurrency / 150
	if conf.workerSettings.Poller < 0 {
		conf.workerSettings.Poller = 1
	}
	conf.workerSettings.Connections = conf.workerSettings.Poller + 10

	logger := GetLogger(conf.Log.Level, conf.Log.File)

	return conf, logger
}

func defaultWorkerSettings() goworker.WorkerSettings {
	return goworker.WorkerSettings{
		Queues:         []string{"resultQueue"},
		Connections:    10,
		Poller:         1,
		UseNumber:      true,
		ExitOnComplete: false,
		Interval:       time.Second,
		IsStrict:       true,
	}
}

func checkConf(conf *Conf) error {
	if conf.AgentToken == "" {
		return errors.New("agent_token must be set")
	}
	if conf.ApiToken == "" {
		return errors.New("api_token must be set")
	}
	if conf.Kafka.Server == "" {
		return errors.New("zookeeper server must be set")
	}
	if len(conf.Kafka.Topics) == 0 {
		return errors.New("zookeeper topics must be set")
	}
	if s, ok := conf.SourceApi["ip"]; !ok || s["url"] == "" {
		return errors.New("source_api.ip must be set")
	}
	if s, ok := conf.SourceApi["domain"]; !ok || s["url"] == "" {
		return errors.New("source_api.domain must be set")
	}
	if s, ok := conf.SourceApi["port"]; !ok || s["url"] == "" {
		return errors.New("source_api.port must be set")
	}
	return nil
}

func defaultConf() *Conf {
	conf := new(Conf)
	conf.ApiPort = 80
	conf.MongoUrl = "mongodb://127.0.0.1:27017/zero"
	conf.RedisUrl = "redis://127.0.0.1:6379/0"
	conf.WorkerNum = 100
	conf.DbFile = server.name + ".db"
	conf.Kafka.Topics = []string{}

	var source = map[string]string{
		"url":      "",
		"auth_id":  "",
		"auth_key": "",
	}
	conf.SourceApi = map[string]map[string]string{}
	conf.SourceApi["ip"] = source
	conf.SourceApi["port"] = source
	conf.SourceApi["domain"] = source
	return conf
}

func createDefaultTomlFile(tomlFile string) error {
	f, err := os.OpenFile(tomlFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	encoder := toml.NewEncoder(f)
	conf := defaultConf()
	err = encoder.Encode(conf)
	return err
}
