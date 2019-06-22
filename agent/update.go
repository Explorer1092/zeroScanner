package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"zeroScannerGo/engine"
)

var (
	pocUpdateLock    sync.Mutex
	sourceUpdateLock sync.Mutex
)

func handleReload() error {
	agent.Logger.Info("reloading ...")
	if atomic.CompareAndSwapInt32(&(agent.restarting), 0, 1) {
		err := stopScanWorker()
		if err != nil {
			agent.Logger.Error(err) // 待完善，发送错误到server端
			return err
		}
		agent.wg.Add(1)
		go func() {
			<-scanExitedChan
			err = restartSelf()
			if err != nil {
				agent.Logger.Error("restartSelf failed:", err)
			}
			agent.wg.Done()
		}()
	}
	agent.Logger.Info("reload succed")
	return nil
}

func handleCookieUpdate(cookieMap map[string]interface{}) error {
	agent.Logger.Info("updating cookie ...")
	tmp := map[string]string{}
	for k, v := range cookieMap {
		tmp[k] = v.(string)
	}
	agent.engine.UpdateCookies(tmp)
	agent.Logger.Info("update cookie succed")
	return nil
}

func handleSourceUpdate(sourceMap map[string]interface{}) error {
	sourceUpdateLock.Lock()
	defer sourceUpdateLock.Unlock()
	agent.Logger.Info("updating source ...")

	tmp := map[string]string{}
	for k, v := range sourceMap {
		tmp[k] = v.(string)
	}
	downloadList := agent.engine.GetSourceDownloadList(tmp)
	agent.engine.RemoveOldSource(tmp)

	if len(downloadList) > 0 {
		if !agent.registered {
			var retry = 3
			var err error
			for retry > 0 {
				retry--
				err = DownloadSource(downloadList)
				if err != nil {
					agent.Logger.Error("update source failed:", err)
				} else {
					break
				}
			}
			if err != nil {
				return err
			}
		} else {
			// 如果扫描器不是等待重启状态，这里用原子操作防止竞争
			if atomic.CompareAndSwapInt32(&(agent.restarting), 0, 1) {
				err := stopScanWorker() //停止扫描
				if err != nil {
					return err
				}
				// 等待worker退出，并重启自身，该函数本身属于worker的一部分，如果不开新的协程，该函数一直不能退出，导致worker不能退出
				agent.wg.Add(1)
				go func() {
					<-scanExitedChan
					err = restartSelf() //重启后会重新注册，自动更新source文件
					if err != nil {
						agent.Logger.Error("restartSelf failed:", err)
					}
					agent.wg.Done()
				}()
				return nil
			}
		}
	}
	agent.Logger.Info("update source succed")

	return nil
}

func handlePocUpdate(pocMap map[string]interface{}) error {
	pocUpdateLock.Lock()
	defer pocUpdateLock.Unlock()
	agent.Logger.Info("updating poc ...")

	tmp := map[string]engine.Poc{}
	for k, v := range pocMap {
		tmp[k] = map2struct(v.(map[string]interface{}))
	}
	downloadList := agent.engine.GetPocDownloadList(tmp)

	if !agent.registered {
		if len(downloadList) > 0 {
			agent.Logger.Info("downloading ...", downloadList)
			err := DownloadPoc(downloadList)
			if err != nil {
				agent.Logger.Fatal("update poc failed:", err) // 待完善，发送错误到server端
			}
		}

		err := agent.engine.UpdatePocs(tmp)
		if err != nil {
			agent.Logger.Fatal("update poc failed:", err) // 待完善，发送错误到server端
		}
		agent.registered = true
		defer agent.Logger.Info("scan start")
	} else {
		if agent.engine.NeedReboot(tmp) {
			// 如果扫描器不是等待重启状态，这里用原子操作防止竞争
			if atomic.CompareAndSwapInt32(&(agent.restarting), 0, 1) {
				err := stopScanWorker()
				if err != nil {
					agent.Logger.Error(err) // 待完善，发送错误到server端
					return err
				}
				// 等待worker退出，并重启自身，该函数本身属于worker的一部分，如果不开新的协程，该函数一直不能退出，导致worker不能退出
				agent.wg.Add(1)
				go func() {
					<-scanExitedChan
					err = restartSelf()
					if err != nil {
						agent.Logger.Error("restartSelf failed:", err)
					}
					agent.wg.Done()
				}()
				return nil
			}
		} else {
			agent.engine.UpdatePocs(tmp) // 不需要重启，说明poc不需要重新load，不会出现错误，所以忽略错误
		}
	}
	agent.Logger.Info("update poc succed")

	return nil
}

func download(method, urlStr string, fileNames []string, timeout time.Duration) ([]byte, error) {
	jsonStr, _ := json.Marshal(fileNames)
	req, err := http.NewRequest(method, urlStr, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(agent.conf.token, agent.conf.token)

	client := new(http.Client)
	client.Timeout = timeout

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return body, nil
}

func DownloadSource(fileNames []string) error {
	urlStr := "http://" + agent.conf.serverHost + "/agent/download/source"
	body, err := download("POST", urlStr, fileNames, time.Minute*5)
	if err != nil {
		return err
	}
	fileList, err := DeCompressZip(body)
	if err != nil {
		return err
	}
	for _, file := range fileList {
		f, err := os.OpenFile(path.Join(engine.SourceDir, file.Name), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		_, err = f.Write(file.Body)
		f.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func DownloadPoc(pocNames []string) error {
	urlStr := "http://" + agent.conf.serverHost + "/agent/download/poc"
	body, err := download("POST", urlStr, pocNames, time.Minute*30)
	if err != nil {
		return err
	}
	fileList, err := DeCompressZip(body)
	if err != nil {
		return err
	}
	for _, file := range fileList {
		f, err := os.OpenFile(path.Join(engine.PocsDir, file.Name), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		_, err = f.Write(file.Body)
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func stopScanWorker() error {
	agent.Logger.Info("stopping scan worker ...")
	err := sendSignal(os.Getpid(), syscall.SIGQUIT) //退出runScan中的worker
	if err != nil {
		agent.Logger.Error(err)
		return err
	}
	return nil
}
