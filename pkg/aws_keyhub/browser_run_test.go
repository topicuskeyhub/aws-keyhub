//go:build !windows

package aws_keyhub

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestDetachProcessStartsNewProcessGroup(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	detachProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != cmd.Process.Pid {
		t.Errorf("expected child to lead its own process group, pgid=%d pid=%d", pgid, cmd.Process.Pid)
	}
	if parent, _ := syscall.Getpgid(0); pgid == parent {
		t.Error("child shares our process group")
	}
}
