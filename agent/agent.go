package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/zhttp"
	"zeroScannerGo/lib/dnscache"
	"zeroScannerGo/lib/glog"
	"zeroScannerGo/lib/goworker"
	"github.com/tidwall/gjson"
	"gopkg.in/redis.v5"
)

var (
	agent          *Agent
	scanExitedChan = make(chan struct{})
)

type Agent struct {
	hostname        string
	ip              string
	conf            *Conf
	Logger          *glog.Logger
	engine          *engine.Engine
	dnsCache        *dnscache.Resolver
	redisClient     *redis.Client
	freeWorkerCount int64
	registered      bool
	restarting      int32 // 0或1 用来标记是否正在等待重启，1为正在等待重启
	Id              string
	wg              sync.WaitGroup
}

func init() {
	agent = newAgent()

	//解析参数
	agent.conf, agent.Logger = flagParse()
	err := checkConf(agent.conf)
	if err != nil {
		agent.Logger.Fatal(err)
	}

	// 初始化agent变量
	agent.Id = fmt.Sprintf("%s:%s-%s", agent.conf.agentType, agent.hostname, agent.ip)
	agent.freeWorkerCount = int64(agent.conf.workerSettings.Concurrency)

	//创建文件夹
	err = mkdirs(engine.SourceDir, engine.PocsDir)
	if err != nil {
		agent.Logger.Fatal(err)
	}
}

func newAgent() *Agent {
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dnsCache := dnscache.New(time.Hour * 36)
	return &Agent{
		hostname: hostname,
		ip:       getSelfIp(),
		dnsCache: dnsCache,
		engine:   engine.New(dnsCache),
	}
}

//向服务端注册
func (a *Agent) register() error {
	agent.Logger.Info("registering ...")
	resp, err := zhttp.Post("http://"+agent.conf.serverHost+"/agent/register", &zhttp.RequestOptions{
		DialTimeout:    time.Second * 5,
		RequestTimeout: time.Second * 5,
		Data: map[string]string{
			"id":   a.Id,
			"type": a.conf.agentType,
		},
		Auth: []string{agent.conf.token, agent.conf.token},
	})
	if err != nil {
		a.Logger.Fatal("register failed", err)
	}
	defer resp.Close()

	var redisUrl, taskQueue string
	if resp.StatusCode() == 200 {
		body := resp.Byte()
		codeR := gjson.GetBytes(body, "code")
		if codeR.Exists() {
			if codeR.Int() == 0 {
				redisUrl = gjson.GetBytes(body, "data.redis_url").Str
				taskQueue = gjson.GetBytes(body, "data.task_queue").Str
			} else {
				msg := gjson.GetBytes(body, "msg").Str
				return errors.New(msg)
			}
		}
	}

	if redisUrl == "" || taskQueue == "" {
		return errors.New(fmt.Sprintf("register failed, statusCode: %d redisUrl: %s taskQueue: %s", resp.StatusCode(), redisUrl, taskQueue))
	}

	parsedRedisUrl, _ := url.Parse(redisUrl)

	if parsedRedisUrl.Hostname() == "127.0.0.1" || parsedRedisUrl.Hostname() == "localhost" {
		parsedRedisUrl.Host = strings.Split(agent.conf.serverHost, ":")[0] + ":" + parsedRedisUrl.Port()
	}

	agent.conf.workerSettings.URI = parsedRedisUrl.String()
	agent.conf.workerSettings.Queues = []string{agent.Id + "_sync", taskQueue, taskQueue}

	err = a.initRedis()
	if err != nil {
		return err
	}

	err = syncAgentInfoToRedis()
	if err != nil {
		return err
	}

	go agent.heartbeat()
	agent.Logger.Info("agent registered")
	return nil
}

//开始扫描
func (a *Agent) runScan() error {
	goworker.Register("scan", scanWorker)
	goworker.Register("sync", syncWorker)

	goworker.SetSettings(a.conf.workerSettings)

	err := goworker.Work()
	if err != nil {
		return err
	}
	close(scanExitedChan)
	return nil
}

func (a *Agent) FreeWorker() int {
	return int(atomic.LoadInt64(&a.freeWorkerCount))
}

func (a *Agent) heartbeat() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := syncAgentInfoToRedis()
			if err != nil {
				agent.Logger.Error(err)
			}
		}
	}
}

func (a *Agent) initRedis() error {
	redisClient, err := newRedisClient(a.conf.workerSettings.URI, 0, 10)
	if err != nil {
		return err
	}
	a.redisClient = redisClient
	return nil
}

func main() {
	err := agent.register()
	if err != nil {
		agent.Logger.Fatal(err)
	}

	// 待完善 网络波动导致扫描worker退出后，不会产生错误，导致程序已经停止了扫描，但并未退出，需要解决网络波动容错的问题
	err = agent.runScan()
	if err != nil {
		agent.Logger.Fatal(err)
	}
	agent.wg.Wait()
}
