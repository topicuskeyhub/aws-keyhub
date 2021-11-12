package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var GitTag = "development"
var GitHash = "unknown"
var GoVersion = "unknown"

func init() {
	rootCmd.AddCommand(versionCommand)
	loginCmd.Flags().StringVar(&roleArn, "version", "", "show aws-keyhub version")
}

var versionCommand = &cobra.Command{
	Use:   "version",
	Short: "show version info",
	Long:  `Show login version`,
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Infof("Version %s (hash: %s, go version: %s)", GitTag, GitHash, GoVersion)
	},
}
