package main

import (
	"strings"
	"sync"
	"time"

	"zeroScannerGo/engine/lib/set"
	"gopkg.in/mgo.v2/bson"
)

const taskTable = "task"
const vulTable = "vul"
const errTable = "err"
const logTable = "log"
const urlLogTable = "urllog"
const MAXSCAN = 300

type SchedulerArgs struct {
	Name                   string                                                //添加任务的时候type参数选择跟该参数一样的值
	Queue                  string                                                //调度器使用的任务队列
	KeyList                []string                                              //调度器存在多种类型的任务时，会依据该列表的顺序逐个检测需要添加到队列中的任务，越靠前优先级越高
	DisabledPocs           *set.Set                                              //针对该调度器禁用的poc，该功能未完成，待完善
	HandleTaskItemListFunc func(*SchedulerArgs, string, []*TaskItem) []*TaskItem //任务去重方法
	GetNewTaskFunc         func(*SchedulerArgs, string) (*Task, error)           //获取新任务的方法
}

type SchedulerManager struct {
	schedulerMap sync.Map
}

func (sm *SchedulerManager) GetSchedulerArgs(name string) *SchedulerArgs {
	scheduler, ok := sm.schedulerMap.Load(name)
	if ok {
		return scheduler.(*Scheduler).args
	}
	return nil
}

func (sm *SchedulerManager) AddVulCount(name, taskId string, count int) {
	scheduler, ok := sm.schedulerMap.Load(name)
	if ok {
		scheduler.(*Scheduler).AddVulCount(taskId, count)
	}
}

func (sm *SchedulerManager) AddDoneCount(name, taskId string, count int) {
	scheduler, ok := sm.schedulerMap.Load(name)
	if ok {
		scheduler.(*Scheduler).AddDoneCount(taskId, count)
	}
}

func (sm *SchedulerManager) PocSwitch(name string, pocNameList []string, mode int) error {
	scheduler, ok := sm.schedulerMap.Load(name)
	if ok {
		disabledPocs := scheduler.(*Scheduler).args.DisabledPocs
		if disabledPocs != nil {
			if len(pocNameList) > 0 {
				var pocNames []interface{}
				for _, pocName := range pocNameList {
					pocNames = append(pocNames, pocName)
				}
				if mode == 0 {
					disabledPocs.Add(pocNames...)
				} else {
					disabledPocs.Remove(pocNames...)
				}
				return setDisabledPocs(name, mode, pocNames...)
			}
		}
	}
	return nil
}

func (sm *SchedulerManager) StopTask(taskIds ...string) {
	sm.schedulerMap.Range(func(k, v interface{}) bool {
		v.(*Scheduler).StopTask(taskIds...)
		return true
	})
}

func (sm *SchedulerManager) Add(args *SchedulerArgs) {
	scheduler := sm.makeScheduler(args)
	scheduler.Run()
	sm.schedulerMap.Store(args.Name, scheduler)
}

func (sm *SchedulerManager) Remove(name string) {
	scheduler, ok := sm.schedulerMap.Load(name)
	if ok {
		scheduler.(*Scheduler).Stop()
		sm.schedulerMap.Delete(name)
	}
}

func (sm *SchedulerManager) makeScheduler(args *SchedulerArgs) *Scheduler {
	scheduler := new(Scheduler)
	if len(args.KeyList) == 0 {
		args.KeyList = []string{"default"}
	}
	scheduler.args = args

	if args.GetNewTaskFunc == nil {
		args.GetNewTaskFunc = defaultGetNewTask
	}

	if args.HandleTaskItemListFunc == nil {
		args.HandleTaskItemListFunc = defaultHandleTaskItemList
	}

	scheduler.Init()
	return scheduler
}

type Scheduler struct {
	args          *SchedulerArgs //调度器相关参数配置
	stop          bool
	allTaskMap    sync.Map             //map[taskid]task //所有的task都在这个map中
	taskTypeMap   map[string]*sync.Map //map[tasktype]map[taskid]task, 根据任务类型分类后的taskMap
	availablePocs []string             //可用poc
	bufQueueCount int
}

func (s *Scheduler) Init() {
	s.taskTypeMap = map[string]*sync.Map{}
	for _, key := range s.args.KeyList {
		s.taskTypeMap[key] = new(sync.Map)
	}
}

// 获取需要添加到任务队列中的任务数量
func (s *Scheduler) taskNum() int {
	var taskNum int
	s.allTaskMap.Range(func(k, v interface{}) bool {
		taskNum += countTaskNum(v.(*Task))
		return true
	})
	return taskNum
}

func countTaskNum(task *Task) int {
	var taskNum int
	task.TaskIter.Range(func(k, v interface{}) bool {
		hostname := strings.Split(k.(string), "_")[0]
		taskItemIter := v.(*TargetIter)
		maxScan := server.scanCount.GetHostMax(hostname)
		if maxScan == 0 {
			if task.Thread > 0 {
				maxScan = task.Thread
			} else {
				maxScan = MAXSCAN
			}
		}
		count := Min(maxScan-server.scanCount.GetHostCount(hostname), taskItemIter.Total)
		if count > 0 {
			taskNum += count
		}
		return true
	})

	return taskNum
}

// 轮询内存中的任务，添加到任务队列中
func (s *Scheduler) handleQueueTask() {
	var sleepTime = time.Second

	for {
		if s.stop {
			return
		}
		// 获取队列任务数与扫描节点信息
		queueCount, totalWorker, freeWorker, err := getQueueCountAndWorker(s.args.Name, s.args.Queue)
		if err != nil {
			server.Logger.Error(err)
			time.Sleep(sleepTime)
			continue
		}

		minQueueCount := int(float64(totalWorker) * 1)
		count := minQueueCount + s.bufQueueCount - queueCount
		// 已经开始扫描后，再进行 bufQueueCount 计算
		if (totalWorker - freeWorker) > 0 {
			percent := count * 100 / (minQueueCount + s.bufQueueCount)
			//			fmt.Println(1, "totalWorker:", totalWorker, "bufQueueCount:", s.bufQueueCount, "queueCount:", queueCount, "percent:", percent)

			// 如果需要添加的任务数量已经占到了总数的60%，则增加bufQueueCount
			if percent > 60 {
				s.bufQueueCount += totalWorker / 10
				if s.bufQueueCount > minQueueCount*5 {
					s.bufQueueCount = minQueueCount * 5
				}
				// 如果需要添加的任务数量小于30%，则减小bufQueueCount
			} else if percent < 30 {
				s.bufQueueCount -= totalWorker / 10
				if s.bufQueueCount < 0 {
					s.bufQueueCount = 0
				}
			}
		}

		//根据任务优先级检测taskMap中的任务
		for _, key := range s.args.KeyList {
			taskMap := s.taskTypeMap[key]
			taskMap.Range(func(k, v interface{}) bool {
				task := v.(*Task)
				// 任务完成
				if task.DoneCount() >= task.Total {
					task.Stop = true

					if task.DoneCount() > task.Total {
						server.Logger.Warn(task.Id, "total:", task.Total, "count:", task.Count, "done:", task.DoneCount())
					}

					// 任务无活动状态超时
				} else if !task.UpdateTime.IsZero() && time.Now().Sub(task.UpdateTime) > task.TimeOut {
					task.TimeOuted = true
					task.Stop = true
				}
				// 任务已经停止
				if task.Stop {
					task.Close()
					if task.TimeOuted {
						server.Logger.Warn(task.Id, "timeouted", "total:", task.Total, "count:", task.Count, "done:", task.DoneCount())
					}
					server.Logger.Info(task.Id, "finish")

					// 如果不是url扫描和资产资产扫描则更新扫描状态和漏洞数量到数据库
					if !strings.HasPrefix(task.Id, "urlscan") && !strings.HasPrefix(task.Id, "sourcescan") &&
						!strings.HasPrefix(task.Id, "urlsourcescan") {
						err := taskUpdateStatusAndVulCount(task.Id, 100, task.VulCount())
						if err != nil {
							if !strings.Contains(err.Error(), "not found") {
								server.Logger.Error(task.Id, "finish failed", err)
								return true
							}
						}
					}

					// 从任务调度中删除该任务
					taskMap.Delete(task.Id)
					s.allTaskMap.Delete(task.Id)
					return true
				}

				if count > 0 && !task.IsEmpty() {
					var urlLogs = []interface{}{}
					for {
						var beforeHandledTaskItemList []*TaskItem
						var tmpCount = count
						var hostCount = map[string]int{}

						task.TaskIter.Range(func(k, v interface{}) bool {
							hostnameKey := k.(string)
							hostname := strings.Split(hostnameKey, "_")[0]

							// 获取域名设置的最大扫描数量
							maxScan := server.scanCount.GetHostMax(hostname)
							if maxScan == 0 {
								if task.Thread > 0 {
									maxScan = task.Thread
								} else {
									maxScan = MAXSCAN
								}
							}
							// 获取域名当前扫描数量，正在扫描数量加上即将添加到队列中的数量
							currentScan := server.scanCount.GetHostCount(hostname) + hostCount[hostname]

							for i := 0; i < Min(maxScan-currentScan, tmpCount); i++ {
								taskItem := task.GetTaskItem(hostnameKey)
								if taskItem != nil {
									beforeHandledTaskItemList = append(beforeHandledTaskItemList, taskItem)
									tmpCount--
									hostCount[hostname]++
									continue
								}
								break
							}
							if tmpCount <= 0 {
								return false
							}
							return true
						})

						if len(beforeHandledTaskItemList) == 0 {
							break
						}

						// Stop去重
						taskItemList := s.args.HandleTaskItemListFunc(s.args, key, beforeHandledTaskItemList)
						task.AddDoneCount(len(beforeHandledTaskItemList) - len(taskItemList)) //过滤掉的任务在task中直接标记为已完成

						for _, taskItem := range taskItemList {
							// 判断相关参数是否已经记录日志，没记录则记录日志
							hash := ParamsHash(taskItem.Params)
							if targetId, ok := task.TargetIdMap[hash]; ok {
								taskItem.Params.TargetId = targetId
							} else {
								targetId := bson.NewObjectId()
								task.TargetIdMap[hash] = targetId.Hex()
								taskItem.Params.TargetId = targetId.Hex()
								urlLogs = append(urlLogs, map[string]interface{}{
									"_id":          targetId,
									"target":       taskItem.Params.ParsedTarget.String(),
									"method":       taskItem.Params.Method,
									"host":         taskItem.Params.ParsedTarget.Host,
									"content_type": taskItem.Params.ContentType,
									"data":         taskItem.Params.Data,
									"time":         time.Now(),
								})
							}

							taskItem.Params.Cookie = task.Cookie
							taskItem.Params.Hosts = task.Hosts[taskItem.Params.ParsedTarget.Hostname()]
							taskItem.Params.UserAgent = task.UserAgent
							// 任务push到队列中
							err := PushTask(task.Queue, task.Id, s.args.Name, taskItem.PocName, taskItem.Params)
							if err != nil {
								server.Logger.Error("pushTask Fail", err)
								task.AddDoneCount(1)
							} else {
								//								task.AddRunningCount(1)
								server.scanCount.AddHostCount(taskItem.Params.ParsedTarget.Hostname(), task.Id, 1)
								task.UpdateTime = time.Now()
								count--
							}
						}
						if count <= 0 {
							break
						}
					}

					if len(urlLogs) > 0 {
						err := urlLogAdd(urlLogs)
						if err != nil {
							server.Logger.Error(err)
						}
					}

					// 如果不是url扫描和资产资产扫描则更新扫描状态和漏洞数量到数据库
					if !strings.HasPrefix(task.Id, "urlscan") && !strings.HasPrefix(task.Id, "sourcescan") &&
						!strings.HasPrefix(task.Id, "urlsourcescan") {
						percent := task.Percent()
						// 因percent为0到100的整数，若percent为0，则会导致数据库中的任务标记为未开始扫描，会造成任务重复扫描
						if percent > 1 {
							err := taskUpdateStatusAndVulCount(task.Id, percent, task.VulCount())
							if err != nil {
								server.Logger.Error(task.Id, "Update status failed", err)
							}
						}
					}
				}
				return true
			})
		}

		time.Sleep(sleepTime)
	}
}

func (s *Scheduler) handleNewTask() {
	var (
		sleepTime = time.Second
		bufCount  = 0
	)
	for {
		time.Sleep(sleepTime)

		if s.stop {
			return
		}

		t := 0
		s.allTaskMap.Range(func(k, v interface{}) bool {
			t++
			return true
		})
		if t >= 2000 {
			continue
		}

		// 获取队列任务数与扫描节点负载
		queueCount, totalWorker, freeWorker, err := getQueueCountAndWorker(s.args.Name, s.args.Queue)
		if err != nil {
			server.Logger.Error(err)
			continue
		}

		taskNum := s.taskNum()
		minQueueCount := int(float64(totalWorker) * 1)
		count := minQueueCount + bufCount - queueCount - taskNum
		needAddCount := minQueueCount + s.bufQueueCount - queueCount

		//		if s.args.Name == "secPublic" {
		//			server.Logger.Debug("taskNum:", taskNum, "count:", count, "needAddCount:", needAddCount)
		//		}

		if needAddCount > 0 && (totalWorker-freeWorker) > 0 {
			percent := taskNum * 100 / needAddCount
			//			fmt.Println(2, "totalWorker:", totalWorker, "bufCount:", bufCount, "queueCount:", queueCount, "taskNum:", taskNum, "percent:", percent)

			// 如果内存中的可用任务数量小于队列需要添加任务数量的3000%，则增加bufCount
			if percent < 3000 {
				bufCount += totalWorker / 10
				if bufCount > minQueueCount*5 {
					bufCount = minQueueCount * 5
				}
				// 如果比例大于5000%，则减小bufCount
			} else if percent > 5000 {
				bufCount -= totalWorker / 10
				if bufCount < 0 {
					bufCount = 0
				}
			}
			//			server.Logger.Debug("percent:", percent, "bufCount:", bufCount)
		}

		if count > 0 {

			//			if s.args.Name == "secPublic" {
			//				server.Logger.Debug(s.args.Name, "count:", count)
			//			}

			for _, key := range s.args.KeyList {
				//根据不同的任务类型从不同的接口获取数据，主要是为了给安全组使用，需要读mongo数据库，读kafka，读资产接口
				task, err := s.args.GetNewTaskFunc(s.args, key)
				if err != nil {
					server.Logger.Error(err)
					continue
				} else if task != nil {
					// 内存中每个host的任务总量计数
					task.Start()

					s.allTaskMap.Store(task.Id, task)
					taskMap := s.taskTypeMap[key]
					taskMap.Store(task.Id, task)

					// 计算任务中可添加到队列中的数量，并减去
					count -= countTaskNum(task)

					//					server.Logger.Debug("task.Id:", task.Id, "total:", task.Total, "count:", count)

					if count <= 0 {
						break
					}
				}
			}
		}
	}
}

// 默认的去重方法
func defaultHandleTaskItemList(s *SchedulerArgs, key string, taskItemList []*TaskItem) []*TaskItem {
	return taskItemList
}

// 默认的获取新任务的方法
func defaultGetNewTask(s *SchedulerArgs, key string) (*Task, error) {
	dbTaskList, err := taskQueryNewInserted(s.Name, 1)
	if err != nil {
		return nil, err
	}

	// 只取了一条，循环一次就返回了
	for _, dbTask := range dbTaskList {
		parsedTargetList, err := parseDBTarget(&dbTask)
		if err != nil {
			taskUpdateStatus(dbTask.Id.Hex(), -1)
			taskUpdateErr(dbTask.Id.Hex(), err.Error())
			continue
		}

		var targetListMap map[string][]ParsedTarget
		var urlReader *ESUrlReader
		var methodFilter *set.SetNonTS
		if len(parsedTargetList) > 0 {
			// 白名单过滤
			parsedTargetList, err = server.whiteList.removeUrlWhiteList(parsedTargetList)
			if err != nil {
				taskUpdateStatus(dbTask.Id.Hex(), -1)
				taskUpdateErr(dbTask.Id.Hex(), err.Error())
				continue
			}

			// 数据按hostname分类
			targetListMap = classifyTarget(parsedTargetList)
		} else {
			urlReader, methodFilter, err = parseUrlReader(&dbTask)
			if err != nil {
				taskUpdateStatus(dbTask.Id.Hex(), -1)
				taskUpdateErr(dbTask.Id.Hex(), err.Error())
				continue
			}
			if urlReader == nil {
				taskUpdateStatus(dbTask.Id.Hex(), -1)
				taskUpdateErr(dbTask.Id.Hex(), "无可扫描target，请检查任务填写是否正确，hosts配置是否正确")
				continue
			}
		}

		task, err := NewTask(&dbTask, s.DisabledPocs, targetListMap, s.Queue)
		if err != nil {
			taskUpdateStatus(dbTask.Id.Hex(), -1)
			taskUpdateErr(dbTask.Id.Hex(), err.Error())
			continue
		}

		// 获取流式读取数据的方法
		if urlReader != nil {
			task.urlReader = urlReader
			task.methodFilter = methodFilter
			// 第一次运行会阻塞
			task.RunStreamHandle()
		}

		err = taskUpdateStatus(dbTask.Id.Hex(), 1)
		if err != nil {
			server.Logger.Error(err)
		}
		return task, nil
	}
	return nil, nil
}

// 任务完成计数
func (s *Scheduler) AddDoneCount(taskId string, count int) {
	task, ok := s.allTaskMap.Load(taskId)
	if ok {
		task.(*Task).AddDoneCount(count)
		task.(*Task).UpdateTime = time.Now()
	}
}

// 漏洞个数计数
func (s *Scheduler) AddVulCount(taskId string, count int) {
	task, ok := s.allTaskMap.Load(taskId)
	if ok {
		task.(*Task).AddVulCount(count)
	}
}

func (s *Scheduler) StopTask(taskIds ...string) {
	for _, taskId := range taskIds {
		task, ok := s.allTaskMap.Load(taskId)
		if ok {
			task.(*Task).Stop = true
		} else {
			err := taskUpdateStatus(taskId, 100)
			if err != nil {
				server.Logger.Error(err)
			}
		}
	}
}

func (s *Scheduler) Run() {
	go s.handleQueueTask()
	go s.handleNewTask()
}

func (s *Scheduler) Stop() {
	s.stop = true
	s.allTaskMap.Range(func(k, v interface{}) bool {
		v.(*Task).Close()
		return true
	})
}
