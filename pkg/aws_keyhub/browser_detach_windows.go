//go:build windows

package aws_keyhub

import (
	"os/exec"
	"syscall"
)

const detachedProcess = 0x00000008 // DETACHED_PROCESS, not exported by package syscall

// detachProcess starts the command without our console and in its own process group, so Ctrl-C or closing the
// terminal does not reach the browser.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess}
}
