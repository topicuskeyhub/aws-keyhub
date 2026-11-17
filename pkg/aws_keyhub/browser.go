package aws_keyhub

import (
	"os/exec"
	"strings"

	"github.com/cli/browser"
	"github.com/sirupsen/logrus"
)

const urlPlaceholder = "{url}"

// openURL opens the link using the configured browserCommand, falling back to the system default browser.
// The configured command is started detached from our terminal. When it cannot be started, or exits with an
// error shortly after, the default browser is used instead.
func openURL(link string) {
	args := buildBrowserCommand(getAwsKeyHubConfig().Keyhub.BrowserCommand, link)
	if args == nil {
		openDefaultBrowser(link)
		return
	}

	logrus.Debugln("Opening browser using configured command:", args)
	cmd := exec.Command(args[0], args[1:]...)
	detachProcess(cmd)
	if err := cmd.Start(); err != nil {
		logrus.Warnln("Failed to start configured browserCommand, falling back to default browser.", err)
		openDefaultBrowser(link)
		return
	}

	// Reap the child and detect a command that started but failed, e.g. an unknown browser profile.
	go func() {
		if err := cmd.Wait(); err != nil {
			logrus.Warnln("Configured browserCommand failed, falling back to default browser.", err)
			openDefaultBrowser(link)
		}
	}()
}

func openDefaultBrowser(link string) {
	if err := browser.OpenURL(link); err != nil {
		logrus.Debugln("Failed to open default browser.", err)
	}
}

// buildBrowserCommand replaces "{url}" in every argument by the link, or appends the link as last argument if no
// argument contains the placeholder. It returns nil when no usable command is configured.
func buildBrowserCommand(configured []string, link string) []string {
	if len(configured) == 0 || strings.TrimSpace(configured[0]) == "" {
		return nil
	}
	args := make([]string, len(configured))
	hasPlaceholder := false
	for i, arg := range configured {
		if strings.Contains(arg, urlPlaceholder) {
			hasPlaceholder = true
			arg = strings.ReplaceAll(arg, urlPlaceholder, link)
		}
		args[i] = arg
	}
	if !hasPlaceholder {
		args = append(args, link)
	}
	return args
}
