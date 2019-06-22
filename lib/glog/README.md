# glog
simple logger

```Go
package main

import (
	"os"

	"github.com/Greyh4t/glog"
)

func main() {
	logger := glog.New(os.Stdout).SetFlags(glog.Ldate | glog.Ltime | glog.Lshortfile | glog.LstdFlags).SetLevel(glog.LevelDebug)
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")
	logger.Panic("panic")
	logger.Fatal("fatal")

	logger.Debugf("%s", "debug")
	logger.Infof("%s", "info")
	logger.Warnf("%s", "warn")
	logger.Errorf("%s", "error")
	logger.Panicf("%s", "panic")
	logger.Fatalf("%s", "fatal")
}
```
