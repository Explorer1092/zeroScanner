package util

import (
	"bytes"
	"os/exec"
	"strconv"
	"time"
)

var LF = "\r\n"

func Exec(command string, timeout time.Duration) (string, string, error) {
	cmd := exec.Command("cmd", "/c", command)
	var o, e bytes.Buffer
	cmd.Stdout = &o
	cmd.Stderr = &e

	err := cmd.Start()
	if err != nil {
		return "", "", err
	}

	if timeout > 0 {
		timer := time.AfterFunc(timeout, func() {
			c := exec.Command("taskkill", "/t", "/f", "/pid", strconv.Itoa(cmd.Process.Pid))
			c.Run()
		})
		defer timer.Stop()
	}

	err = cmd.Wait()

	return string(GBK2UTF8(o.Bytes())), string(GBK2UTF8(e.Bytes())), err
}
