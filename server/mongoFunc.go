package main

import (
	"errors"
	"time"

	"zeroScannerGo/engine"
	"gopkg.in/mgo.v2/bson"
)

type TaskStatusQuery struct {
	Id     bson.ObjectId `bson:"_id"` //任务id
	Status int
}

func getRunningSpiderTask(taskType string, num int) ([]DBTask, error) {
	var (
		spiderTasks []DBTask
		m           = &[]bson.M{
			{"$match": &bson.M{"type": taskType, "spider_info.status": &bson.M{"$in": []int{1, 2}}}},
			{"$sort": &bson.M{"createtime": 1}},
			{"$limit": num},
		}
	)

	s := server.mongoDriver.Get()
	defer s.Close()

	err := s.DB(server.mongoDriver.DbName).C(taskTable).Pipe(m).All(&spiderTasks)
	if err != nil {
		return nil, err
	}
	return spiderTasks, nil
}

func updateSpiderTaskStartTime(taskId bson.ObjectId) error {
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(taskTable).UpdateId(taskId, &bson.M{"$set": &bson.M{"spider_info.starttime": time.Now(), "spider_info.status": 2}})
}

func updateSpiderTaskTarget(taskId bson.ObjectId, spiderStatus int, target []string) error {
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(taskTable).UpdateId(taskId, &bson.M{"$set": &bson.M{"status": 0, "target": target, "spider_info.status": spiderStatus}})
}

func updateSpiderTaskFetchedUrls(taskId string, fetchedUrls []string) error {
	if !bson.IsObjectIdHex(taskId) {
		return errors.New(taskId + " is not a correct taskId")
	}
	s := server.mongoDriver.Get()
	defer s.Close()

	return s.DB(server.mongoDriver.DbName).C(taskTable).UpdateId(bson.ObjectIdHex(taskId),
		&bson.M{"$set": &bson.M{"spider_info.url_fetched": true, "spider_info.fetched_urls": fetchedUrls}})
}

func taskAdd(task *DBTask) (string, error) {
	if task.Id == "" {
		task.Id = bson.NewObjectId()
	}
	task.CreateTime = time.Now().Local()
	s := server.mongoDriver.Get()
	defer s.Close()
	return task.Id.Hex(), s.DB(server.mongoDriver.DbName).C(taskTable).Insert(task)
}

func taskDeleteByTaskIds(taskIds []string) error {
	if len(taskIds) > 0 {
		var params []bson.ObjectId
		for _, taskId := range taskIds {
			if !bson.IsObjectIdHex(taskId) {
				return errors.New("invalid taskid: " + taskId)
			}
			params = append(params, bson.ObjectIdHex(taskId))
		}

		s := server.mongoDriver.Get()

		_, err := s.DB(server.mongoDriver.DbName).C(taskTable).RemoveAll(&bson.M{"_id": &bson.M{"$in": params}})
		if err != nil {
			s.Close()
			return err
		}
		go func() {
			s.DB(server.mongoDriver.DbName).C(vulTable).RemoveAll(&bson.M{"taskid": &bson.M{"$in": taskIds}})
			s.DB(server.mongoDriver.DbName).C(errTable).RemoveAll(&bson.M{"taskid": &bson.M{"$in": taskIds}})
			s.DB(server.mongoDriver.DbName).C(logTable).RemoveAll(&bson.M{"taskid": &bson.M{"$in": taskIds}})
			s.Close()
		}()
	}
	return nil
}

func vulAdd(vul engine.Result) error {
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(vulTable).Insert(vul)
}

func errAdd(err engine.Result) error {
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(errTable).Insert(err)
}

func logAdd(log engine.Result) error {
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(logTable).Insert(log)
}

//func taskUpdateVulCount(table string, taskId string, vulCount int) error {
//	s := server.mongoDriver.Get()
//	defer s.Close()
//	if !bsonIdpattern.MatchString(taskId) {
//		return errors.New(taskId + " is not a correct taskId")
//	}
//	return s.DB(server.mongoDriver.DbName).C(table).UpdateId(bson.ObjectIdHex(taskId), &bson.M{"$set": &bson.M{"vul": vulCount}})
//}

//func taskUpdateVul(taskId string, vul map[string]interface{}) error {
//	s := server.mongoDriver.Get()
//	defer s.Close()
//	if !bsonIdpattern.MatchString(taskId) {
//		return errors.New(taskId + " is not a correct taskId")
//	}
//	return s.DB(server.mongoDriver.DbName).C("task").UpdateId(bson.ObjectIdHex(taskId), &bson.M{"$addToSet": &bson.M{"vul": vul}})
//}

func taskUpdateErr(taskId, errMsg string) error {
	if !bson.IsObjectIdHex(taskId) {
		return errors.New(taskId + " is not a correct taskId")
	}
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(taskTable).UpdateId(bson.ObjectIdHex(taskId), &bson.M{"$addToSet": &bson.M{"err": errMsg}})
}

func taskUpdateStatus(taskId string, status int) error {
	if !bson.IsObjectIdHex(taskId) {
		return errors.New(taskId + " is not a correct taskId")
	}
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(taskTable).UpdateId(bson.ObjectIdHex(taskId), &bson.M{"$set": &bson.M{"status": status}})
}

func taskUpdateStatusAndVulCount(taskId string, status, vulCount int) error {
	if !bson.IsObjectIdHex(taskId) {
		return errors.New(taskId + " is not a correct taskId")
	}
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(taskTable).UpdateId(bson.ObjectIdHex(taskId), &bson.M{"$set": &bson.M{"status": status, "vul": vulCount}})
}

func taskQueryNewInserted(taskType string, num int) ([]DBTask, error) {
	var result []DBTask
	m := &[]bson.M{
		{"$match": &bson.M{"status": 0, "type": taskType}},
		{"$sort": &bson.M{"createtime": 1}},
		{"$limit": num},
	}
	s := server.mongoDriver.Get()
	defer s.Close()
	err := s.DB(server.mongoDriver.DbName).C(taskTable).Pipe(m).All(&result)
	return result, err
}

func taskQueryStatusByTaskIds(taskIds []string) (map[string]int, error) {
	var (
		result = map[string]int{}
		params []bson.ObjectId
	)
	for _, taskId := range taskIds {
		if bson.IsObjectIdHex(taskId) {
			params = append(params, bson.ObjectIdHex(taskId))
		} else {
			return nil, errors.New("Wrong task id format: " + taskId)
		}
	}
	if len(params) > 0 {
		s := server.mongoDriver.Get()
		defer s.Close()
		var tmp []TaskStatusQuery
		err := s.DB(server.mongoDriver.DbName).C(taskTable).Find(&bson.M{"_id": &bson.M{"$in": params}}).All(&tmp)
		if err != nil {
			return nil, err
		}
		for _, t := range tmp {
			result[t.Id.Hex()] = t.Status
		}
	}
	return result, nil
}

func urlLogAdd(logs []interface{}) error {
	s := server.mongoDriver.Get()
	defer s.Close()
	return s.DB(server.mongoDriver.DbName).C(urlLogTable).Insert(logs...)
}

//func taskQueryByTaskIds(taskIds []string) ([]DBSaveTask, error) {
//	var (
//		result []DBSaveTask
//		params []bson.ObjectId
//	)
//	for _, taskId := range taskIds {
//		if bsonIdpattern.MatchString(taskId) {
//			params = append(params, bson.ObjectIdHex(taskId))
//		}
//	}
//	s := mongoDriver.Get()
//	defer s.Close()
//	err := s.DB(mongoDriver.DbName).C("task").Find(&bson.M{"_id": &bson.M{"$in": params}}).All(&result)
//	return result, err
//}

//func taskQueryOne() (DBSaveTask, error) {
//	var result = DBSaveTask{}
//	s := mongoDriver.Get()
//	defer s.Close()
//	err := s.DB(mongoDriver.DbName).C("task").Find(&bson.M{}).One(&result)
//	return result, err
//}
