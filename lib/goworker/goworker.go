package goworker

import (
	"os"
	"strconv"
	"sync"
	"time"

	"zeroScannerGo/lib/glog"

	"gopkg.in/redis.v5"
)

var (
	logger      *glog.Logger
	redisClient *redis.Client
	initMutex   sync.Mutex
	initialized bool
)

var workerSettings WorkerSettings

type WorkerSettings struct {
	QueuesString   string
	Queues         queuesFlag
	Interval       time.Duration
	Concurrency    int
	Connections    int
	Poller         int
	URI            string
	Namespace      string
	ExitOnComplete bool
	IsStrict       bool
	UseNumber      bool
}

func SetSettings(settings WorkerSettings) {
	workerSettings = settings
}

// Init initializes the goworker process. This will be
// called by the Work function, but may be used by programs
// that wish to access goworker functions and configuration
// without actually processing jobs.
func Init() error {
	initMutex.Lock()
	defer initMutex.Unlock()
	if !initialized {
		logger = glog.New(os.Stdout).SetFlags(glog.Lshortfile | glog.LstdFlags).SetLevel(glog.LevelInfo)

		err := flags()
		if err != nil {
			return err
		}

		redisClient, err = newRedisClient(workerSettings.URI, workerSettings.Connections)
		if err != nil {
			return err
		}

		initialized = true
	}
	return nil
}

// Close cleans up resources initialized by goworker. This
// will be called by Work when cleaning up. However, if you
// are using the Init function to access goworker functions
// and configuration without processing jobs by calling
// Work, you should run this function when cleaning up. For
// example,
//
//	if err := goworker.Init(); err != nil {
//		fmt.Println("Error:", err)
//	}
//	defer goworker.Close()
func Close() {
	initMutex.Lock()
	defer initMutex.Unlock()
	if initialized {
		redisClient.Close()
		initialized = false
	}
}

// Work starts the goworker process. Check for errors in
// the return value. Work will take over the Go executable
// and will run until a QUIT, INT, or TERM signal is
// received, or until the queues are empty if the
// -exit-on-complete flag is set.
func Work() error {
	err := Init()
	if err != nil {
		return err
	}
	defer Close()

	ctx := signals()

	poller, err := newPoller(workerSettings.Queues, workerSettings.IsStrict)
	if err != nil {
		return err
	}
	jobs := poller.poll(workerSettings.Poller, workerSettings.Interval, ctx)

	var monitor sync.WaitGroup

	for id := 0; id < workerSettings.Concurrency; id++ {
		worker, err := newWorker(strconv.Itoa(id), workerSettings.Queues)
		if err != nil {
			return err
		}
		worker.work(jobs, &monitor)
	}

	monitor.Wait()

	return nil
}
