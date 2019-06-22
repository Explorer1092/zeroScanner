package main

import (
	"errors"
	"flag"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/lib/dnscache"
	"zeroScannerGo/lib/glog"
	"zeroScannerGo/lib/goworker"

	"gopkg.in/redis.v5"
)

var (
	server *Server
)

type Server struct {
	name             string
	conf             *Conf
	Logger           *glog.Logger
	pocDb            *PocDb
	redisClient      *redis.Client
	cookieHandler    *CookieHandler
	mongoDriver      MongoDriver
	whiteList        *WhiteList        //处理各种任务的白名单
	schedulerManager *SchedulerManager //调度器管理
	kafkaUrlReader   *KafkaUrlReader
	esUrlReader      *ESUrlReader
	sourceReader     *SourceReader
	scanSettings     ScanSettings
	portServiceMap   map[string]string
	servicePortMap   map[string]string
	pocIterMap       map[string]*Iter

	scanCount *ScanCount

	dnsCache *dnscache.Resolver
}

type ScanSettings struct {
	ScanUrlRealTime bool //url实时扫描
	ScanUrlSource   bool //url资产扫描
	//	ScanUrlSourceDelay time.Duration //url资产扫描时间间隔
	//	ScanUrlSourceNextTime time.Time     //url资产扫描下次扫描时间
	ScanSource         bool          //资产定时扫描
	ScanSourceDelay    time.Duration //资产定时扫描间隔
	ScanSourceNextTime time.Time     //资产定时扫描下次扫描时间
}

func init() {
	var tomlFile string
	flag.StringVar(&tomlFile, "c", getSelfName()+".toml", "toml format configuration file")
	flag.Parse()

	switch flag.Arg(0) {
	case "checkPoc":
		checkSoFile()
	case "testPoc":
		testSoFile()
	default:
		serverInit(tomlFile)
	}
}

func serverInit(tomlFile string) {
	server = newServer()

	// 解析配置文件
	if tomlFile == "" {
		tomlFile = server.name + ".toml"
	}
	server.conf, server.Logger = confParse(tomlFile)
	err := checkConf(server.conf)
	if err != nil {
		server.Logger.Fatal(err)
	}

	// 创建文件夹
	err = mkdirs(engine.SourceDir, engine.PocsDir, engine.DictsDir)
	if err != nil {
		server.Logger.Fatal(err)
	}

	// 初始化dns缓存
	server.dnsCache = dnscache.New(time.Second * 10)
}

func newServer() *Server {
	return &Server{
		name: getSelfName(),
	}
}

func initRedis() error {
	redisClient, err := newRedisClient(server.conf.RedisUrl, 0, 10)
	if err != nil {
		return err
	}
	server.redisClient = redisClient
	return nil
}

func initSourceReader() {
	server.sourceReader = new(SourceReader)
	server.sourceReader.Init(server.conf.SourceApi)
}

func initUrlReader() error {
	server.kafkaUrlReader = new(KafkaUrlReader)
	// 调试模式关闭连接kafka功能
	err := server.kafkaUrlReader.Init(server.conf.Kafka.Server, server.conf.Kafka.Topics)
	if err != nil {
		return errors.New("zookeeper: " + err.Error())
	}

	server.esUrlReader = NewEsUrlReader()
	err = server.esUrlReader.AutoRefreshHostList(time.Hour * 24)
	if err != nil {
		return errors.New("es:" + err.Error())
	}

	return nil
}

func initWhiteList() error {
	server.whiteList = &WhiteList{
		redisUrl: server.conf.RedisUrl,
		db:       1,
		poolSize: 10,
	}
	return server.whiteList.init()
}

func initHttpApi() error {
	return newHttpServer(server.conf.ApiPort)
}

func initPocDb() error {
	server.pocDb = new(PocDb)
	if server.conf.DbFile != "" {
		return server.pocDb.Init(server.conf.DbFile)
	}
	return server.pocDb.Init(server.name + ".db")
}

func initPoc() error {
	pocMap, err := loadPoc(nil)
	if err != nil {
		return err
	}
	pocIterMap := map[string]*Iter{}
	for _, poc := range pocMap {
		pocIter, err := parsePoc(poc)
		if err != nil {
			return err
		}
		pocIterMap[poc.Name] = pocIter
	}
	server.pocIterMap = pocIterMap
	return nil
}

func initMongo() error {
	server.mongoDriver = MongoDriver{
		MgoUrl: server.conf.MongoUrl,
		DbName: "zero",
	}
	if err := server.mongoDriver.Init(); err != nil {
		return errors.New("mongo: " + err.Error())
	}
	return nil
}

func initCookieHandler() error {
	server.cookieHandler = new(CookieHandler)
	server.cookieHandler.Init()
	return nil
}

func initGoworker() {
	goworker.SetSettings(server.conf.workerSettings)
	goworker.Register("saveScanResult", saveScanResultWorker) //处理扫描结果
}

func initScheduler() {
	server.schedulerManager = new(SchedulerManager)
	server.schedulerManager.Add(newSecPublicSchedulerArgs())
	server.schedulerManager.Add(newSecPrivateSchedulerArgs())
	server.schedulerManager.Add(newTechPublicSchedulerArgs())
	server.schedulerManager.Add(newTechPrivateSchedulerArgs())
}

func initPortServiceMap() {
	var err error
	server.portServiceMap, server.servicePortMap, err = parseNampServices("nmap-services")
	if err != nil {
		server.Logger.Error(err)
	}
}

func initScanCount() error {
	scanMax, err := getScanMax()
	if err != nil {
		return err
	}
	server.scanCount = NewScanCount()
	server.scanCount.SetHostMax(scanMax)
	return nil
}

func Start() error {
	server.scanSettings = ScanSettings{
		ScanSourceDelay: 24 * 60 * time.Minute,
	}

	initGoworker()
	initSourceReader()

	err := initRedis()
	if err != nil {
		return err
	}

	err = initMongo()
	if err != nil {
		return err
	}

	err = initUrlReader()
	if err != nil {
		return err
	}

	err = initPocDb()
	if err != nil {
		return err
	}

	err = initWhiteList()
	if err != nil {
		return err
	}

	err = initScanCount()
	if err != nil {
		return err
	}

	err = initPoc()
	if err != nil {
		return err
	}

	err = initCookieHandler()
	if err != nil {
		return err
	}

	initScheduler()
	initPortServiceMap()

	err = initHttpApi()
	if err != nil {
		return err
	}

	server.Logger.Info("started")
	return goworker.Work()
}

func main() {
	err := Start()
	if err != nil {
		server.Logger.Fatal(err)
	}
}
