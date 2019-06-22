package main

import (
	"time"
)

type Cookie interface {
	generateCookie() bool
	updateCookie(force bool) (bool, bool) //前者是否更新成功（可能cookie有效，并没有真实更新），后者是否是真实更新
	buildCookie() string
	getRefreshPeriod() int
	getUpdateTime() time.Time
	flush()
}

type CookieHandler struct {
	cookies map[string]Cookie
	closed  bool //刷新cookie时用到，如果关闭了就不刷新cookie
	inited  bool
	synced  bool //同步到agent
}

//添加cookie
func (self *CookieHandler) AddCookie(pin string, password string, erpUser string, erpPass string, ckType string, ckRefreshMinute int) {
	var ck Cookie
	if ckType == "JD" {
		ck = &CookieJd{
			pin:           pin,
			password:      password,
			erpUser:       erpUser,
			erpPass:       erpPass,
			cookies:       map[string]string{},
			refreshMinute: ckRefreshMinute,
		}
	}
	ck.generateCookie()
	self.cookies[pin] = ck
}

//删除cookie
func (self *CookieHandler) DelCookie(pin string) {
	delete(self.cookies, pin)
	self.synced = false
}

//设置默认cookie
func (self *CookieHandler) SetDefault(pin string) {
	self.cookies["default"] = self.cookies[pin]
	self.synced = false
}

func (self *CookieHandler) GetCookie(pin string) string {
	if pin == "" {
		pin = "default"
	}
	c, ok := self.cookies[pin]
	if !ok {
		server.Logger.Debug("can't find cookie of pin:", pin)
		return ""
	}
	return c.buildCookie()
}

func (self *CookieHandler) Update(pin string) (bool, bool) {
	return self.cookies[pin].updateCookie(false)
}
func (self *CookieHandler) UpdateAll() {
	for _, v := range self.cookies {
		v.updateCookie(false)
	}
}

//停止自动刷新线程
func (self *CookieHandler) Close() {
	self.closed = true
}

//获取所有cookie
func (self *CookieHandler) Cookies() map[string]string {
	cookies := map[string]string{}
	for pin, ck := range self.cookies {
		cookies[pin] = ck.buildCookie()
	}
	return cookies
}

//定时刷新cookie
func (self *CookieHandler) run() {
	go func() {
		for {
			if self.closed {
				break
			}
			//pin更确切的说是index,c中也包含pin
			for pin, ck := range self.cookies {
				if pin != "default" {
					//按照cookie设定的刷新时间刷新
					if int(time.Now().Sub(ck.getUpdateTime()).Seconds()) > (ck.getRefreshPeriod() * 60) {
						updateSucc, realUpdate := ck.updateCookie(false)
						if updateSucc && realUpdate {
							self.synced = false
						}
					}
				}
			}
			//指针指向的内容变了，指针没变，没必要修改default cookie
			//同步到agent端
			if !self.synced {
				err := SyncToAgent(self.Cookies(), nil, nil)
				if err != nil {
					server.Logger.Error(err)
				} else {
					self.synced = true
				}
			}
			self.inited = true
			time.Sleep(time.Second)
		}
	}()
}

func (self *CookieHandler) Init() {
	self.cookies = map[string]Cookie{}
	self.AddCookie("waimianyougesongshu", "qwerasdf,", "langguoquan", "!#%Lyp82ndlfdj1", "JD", 10)
	self.SetDefault("waimianyougesongshu")
	self.run()
	for !self.inited { //等待初始化完成
		time.Sleep(500 * time.Millisecond)
	}
}

//重置
func (self *CookieHandler) ReSet() {
	self.cookies = map[string]Cookie{}
	self.AddCookie("waimianyougesongshu", "qwerasdf,", "langguoquan", "!#%Lyp82ndlfdj1", "JD", 10)
	self.SetDefault("waimianyougesongshu")
}

//置空所有的cookie
func (self *CookieHandler) Flush() {
	for _, ck := range self.cookies {
		ck.flush()
	}
}
