package util

import (
	"bytes"
	"os/exec"
	"syscall"
	"time"
)

func Exec(command string, timeout time.Duration) (string, string, error) {
	cmd := exec.Command("bash", "-c", command)
	var o, e bytes.Buffer
	cmd.Stdout = &o
	cmd.Stderr = &e
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err := cmd.Start()
	if err != nil {
		return "", "", err
	}

	if timeout > 0 {
		timer := time.AfterFunc(timeout, func() {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		})
		defer timer.Stop()
	}

	err = cmd.Wait()

	return o.String(), e.String(), err
}
