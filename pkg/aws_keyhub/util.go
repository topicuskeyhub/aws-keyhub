package aws_keyhub

import (
	"github.com/sirupsen/logrus"
	"os"
)

func getUserHomeDir() string {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		logrus.Fatal(err)
	}
	return userHomeDir
}
