package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "aws-keyhub",
		Short: "login on the AWS CLI via Topicus KeyHub",
		Long: `aws-keyhub retrieves temporary (session) credentials by using Topicus KeyHub. By doing a 
OAuth2 token exchange for the SAML assertion with KeyHub. This SAML assertion is then used to retrieve
credentials from AWS STS.`,
	}
)
var Verbose bool

func Execute() error {
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	return rootCmd.Execute()
}
