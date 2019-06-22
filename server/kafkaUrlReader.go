package main

import (
	"time"

	"strings"

	"github.com/Shopify/sarama"
	"github.com/bsm/sarama-cluster"
)

type KafkaUrlReader struct {
	ZookeeperServer string
	consumerGroup   string
	Topics          []string
	consumer        *cluster.Consumer
	timeoutCounter  int
}

func (self *KafkaUrlReader) Init(ZookeeperServer string, topics []string) error {
	self.consumerGroup = "zero_scanner_go"
	self.ZookeeperServer = ZookeeperServer
	self.Topics = topics
	config := cluster.NewConfig()
	config.Consumer.Return.Errors = true
	config.Consumer.Offsets.CommitInterval = 10 * time.Second
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	consumer, err := cluster.NewConsumer(strings.Split(self.ZookeeperServer, ","), self.consumerGroup, self.Topics, config)
	if err != nil {
		return err
	}
	self.consumer = consumer
	self.timeoutCounter = 0
	return nil
}

func (self *KafkaUrlReader) check(urlStr string, dangerKeys []string, logoutKeys []string) bool {
	_, url, _, data := parseMethod(urlStr)
	//	method, url, _, data := parseMethod(urlStr)
	//	if method == "POST" {
	//		return false
	//	}

	if hasDangerKey(url, dangerKeys) || hasDangerKey(data, dangerKeys) {
		return false
	}

	if hasLogoutKey(url, logoutKeys) {
		return false
	}

	return true
}

func (self *KafkaUrlReader) Read(num int) []string {
	var (
		count      int
		urls       []string
		timer      = time.NewTimer(time.Second)
		dangerKeys []string
		logoutKeys []string
	)
	var err error
	dangerKeys, err = server.whiteList.getKeywordItems()
	if err != nil {
		server.Logger.Error(err)
	}
	if len(dangerKeys) == 0 {
		dangerKeys = []string{"aid", "sid", "token", "key", "uuid", "sign", "auth", "ticket"}
	}

	logoutKeys, err = server.whiteList.getLogoutItems()
	if err != nil {
		server.Logger.Error(err)
	}
	if len(logoutKeys) == 0 {
		logoutKeys = []string{"logout", "loginout", "exit", "quit"}
	}

loop:
	for {
		select {
		case msg, ok := <-self.consumer.Messages():
			if ok {
				//You only need to call MarkOffset as CommitOffset will be called automatically every Config.Consumer.Offsets.CommitInterval (see https://godoc.org/github.com/Shopify/sarama#Config)
				self.consumer.MarkOffset(msg, "") // mark message as processed
				url := strings.TrimSpace(string(msg.Value))
				if url != "" {
					if self.check(url, dangerKeys, logoutKeys) {
						urls = append(urls, url)
						count++
					}
				}
				self.timeoutCounter = 0 //读取成功就重置计数器
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(time.Second)
			}
			if count >= num {
				break loop
			}
		case <-timer.C:
			server.Logger.Debug("url read timeout")
			if count == 0 {
				self.timeoutCounter++
				//如果连续60次以上出现超时，则重启Kafka consumer，并返回结果
				if self.timeoutCounter >= 60 {
					self.Restart()
				}
			}
			break loop
		}
	}

	timer.Stop()
	return urls
}

func (self *KafkaUrlReader) Close() error {
	return self.consumer.Close()
}

func (self *KafkaUrlReader) Restart() {
	server.Logger.Error("kafka consumer restart")
	self.Close()
	self.Init(self.ZookeeperServer, self.Topics)
}

func hasLogoutKey(s string, keys []string) bool {
	// 过滤logout链接
	tmp := strings.SplitN(s, "://", 2)
	if len(tmp) == 2 {
		s = tmp[1]
	}
	s = strings.ToLower(s)

	ts := []string{"?", "/", "="}
	for _, key := range keys {
		for _, t := range ts {
			if strings.Contains(s, key+t) || strings.Contains(s, t+key) {
				return true
			}
		}
	}
	return isDangerDomain(s)
}

func hasDangerKey(s string, keys []string) bool {
	// 过滤危险关键字
	s = strings.ToLower(s)
	for _, key := range keys {
		if strings.Contains(s, key+"=") || strings.Contains(s, key+`%22`) || strings.Contains(s, key+`"`) {
			return true
		}
	}
	return false
}

func isDangerDomain(s string) bool {
	// 过滤危险网站
	s = strings.SplitN(s, "/", 2)[0]
	if strings.HasSuffix(s, ".gov.cn") {
		return true
	}
	return false
}
