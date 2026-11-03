//go:build !windows

package aws_keyhub

import (
	"os/exec"
	"syscall"
)

// detachProcess starts the command in its own session, so Ctrl-C or closing the terminal (SIGINT/SIGHUP) does
// not reach the browser.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
