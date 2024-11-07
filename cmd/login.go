package cmd

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/topicuskeyhub/aws-keyhub/pkg/aws_keyhub"
)

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVarP(&roleArn, "role-arn", "r", "", "login with the specified role ARN instead of asking for the role you want to login with")
	loginCmd.Flags().StringVarP(&profile, "profile", "p", "keyhub", "aws profile to write the credentials to")
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
var profile string

func login() {
	aws_keyhub.CheckIfAwsKeyHubConfigFileExists()
	aws_keyhub.CheckIfAwsConfigFileExists()
	ctx := context.Background()

	authorizeDeviceResponse := aws_keyhub.AuthorizeDevice()
	loginResponse := aws_keyhub.PollForAccessToken(authorizeDeviceResponse, 0)
	exchangeTokenResponse := aws_keyhub.ExchangeToken(loginResponse)
	samlResponseDecoded := aws_keyhub.DecodeSAMLResponse(exchangeTokenResponse.AccessToken)
	rolesAndPrincipals := aws_keyhub.RolesAndPrincipalsFromSamlResponse(samlResponseDecoded)

	var samlOutput *sts.AssumeRoleWithSAMLOutput

	selectedRoleAndPrincipal := aws_keyhub.SelectRoleAndPrincipal(roleArn, rolesAndPrincipals)
	samlOutput = aws_keyhub.StsAssumeRoleWithSAML(ctx, selectedRoleAndPrincipal.Principal, selectedRoleAndPrincipal.Role, exchangeTokenResponse.AccessToken)

	aws_keyhub.WriteCredentialFile(profile, samlOutput.Credentials)
	aws_keyhub.VerifyIfLoginWasSuccessful(ctx, profile, selectedRoleAndPrincipal.Role)
	logrus.Infof("Successfully logged in, use the AWS profile `%[1]s`. (export AWS_PROFILE=%[1]s / set AWS_PROFILE=%[1]s / $env:AWS_PROFILE='%[1]s')", profile)
}
