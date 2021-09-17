package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/topicuskeyhub/aws-keyhub/pkg/aws_keyhub"
)

func init() {
	rootCmd.AddCommand(configureCmd)
}

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "configure settings",
	Long:  `Configure the settings for aws-keyhub`,
	Run: func(cmd *cobra.Command, args []string) {
		if Verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}
		configure()
	},
}

func configure() {
	aws_keyhub.ConfigureAwsKeyhub()
	logrus.Infoln("Configuration of aws-keyhub completed. You can now use the `login` command.")
}
