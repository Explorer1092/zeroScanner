package engine

import (
	"sync"
)

var GetCookie = func(string) string {
	return "GetCookie function is not initialized"
}

type cookies struct {
	m         sync.RWMutex
	cookieMap map[string]string
}

func (self *cookies) Get(name string) string {
	if name == "" {
		name = "default"
	}
	self.m.RLock()
	defer self.m.RUnlock()
	return self.cookieMap[name]
}

func (self *cookies) Update(cookieMap map[string]string) {
	self.m.Lock()
	self.cookieMap = cookieMap
	self.m.Unlock()
}

func InitCookie(getCookie func(string) string) {
	GetCookie = getCookie
}
