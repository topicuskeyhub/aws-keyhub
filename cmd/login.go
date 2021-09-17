package cmd

import (
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/topicuskeyhub/aws-keyhub/pkg/aws_keyhub"
)

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVarP(&roleArn, "role-arn", "r", "", "login with the specified role ARN instead of prompting")
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to AWS",
	Long:  `Starts the login flow to retrieve AWS credentials`,
	Run: func(cmd *cobra.Command, args []string) {
		if Verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}
		login()
	},
}

var roleArn string

func login() {
	aws_keyhub.CheckIfAwsKeyHubConfigFileExists()
	aws_keyhub.CheckIfAwsConfigFileExists()

	authorizeDeviceResponse := aws_keyhub.AuthorizeDevice()
	loginResponse := aws_keyhub.PollForAccessToken(authorizeDeviceResponse, 0)
	exchangeTokenResponse := aws_keyhub.ExchangeToken(loginResponse)
	samlResponseDecoded := aws_keyhub.DecodeSAMLResponse(exchangeTokenResponse.AccessToken)
	rolesAndPrincipals := aws_keyhub.RolesAndPrincipalsFromSamlResponse(samlResponseDecoded)

	var samlOutput *sts.AssumeRoleWithSAMLOutput

	selectedRoleAndPrincipal := aws_keyhub.SelectRoleAndPrincipal(roleArn, rolesAndPrincipals)
	samlOutput = aws_keyhub.StsAssumeRoleWithSAML(selectedRoleAndPrincipal.Principal, selectedRoleAndPrincipal.Role, exchangeTokenResponse.AccessToken)

	aws_keyhub.WriteCredentialFile(samlOutput.Credentials)
	aws_keyhub.VerifyIfLoginWasSuccessful(selectedRoleAndPrincipal.Role)
	logrus.Infoln("Successfully logged in, use the AWS profile `keyhub`. (export AWS_PROFILE=keyhub / set AWS_PROFILE=keyhub / $env:AWS_PROFILE='keyhub')")
}
