package main

import (
	"gopkg.in/mgo.v2"
)

type MongoDriver struct {
	MgoUrl     string
	DbName     string
	mgoSession *mgo.Session
}

func (self *MongoDriver) Init() error {
	var err error
	self.mgoSession, err = mgo.Dial(self.MgoUrl)
	if err != nil {
		return err
	}
	self.mgoSession.SetPoolLimit(1000)
	self.mgoSession.SetMode(mgo.Monotonic, true)
	return nil
}

func (self *MongoDriver) Get() *mgo.Session {
	if self.mgoSession == nil {
		self.Init()
	}
	if self.mgoSession.Ping() != nil {
		self.mgoSession.Refresh()
	}
	return self.mgoSession.Clone()
}
