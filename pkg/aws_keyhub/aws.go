package aws_keyhub

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
	"os"
	"strings"
)

func StsAssumeRoleWithSAML(context context.Context, principalArn string, roleArn string, samlAssertion string) *sts.AssumeRoleWithSAMLOutput {
	awsKeyHubConfig := getAwsKeyHubConfig()
	input := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int32(awsKeyHubConfig.Aws.AssumeDuration),
		PrincipalArn:    aws.String(principalArn),
		RoleArn:         aws.String(roleArn),
		SAMLAssertion:   aws.String(samlAssertion),
	}

	cfg, err := config.LoadDefaultConfig(context)
	if err != nil {
		logrus.Fatal("Could not setup config for sts call: ", err)
	}

	svc := sts.NewFromConfig(cfg)
	result, err := svc.AssumeRoleWithSAML(context, input)

	if err != nil {
		logrus.Fatal("AWS STS AssumeRoleWithSAML failed:", err)
	}
	logrus.Debugln("AWS STS AssumeRoleWithSAML result:", result)
	return result
}

func VerifyIfLoginWasSuccessful(context context.Context, profile string, roleArn string) {
	cfg, err := config.LoadDefaultConfig(context, config.WithSharedConfigProfile(profile))
	svc := sts.NewFromConfig(cfg)

	input := &sts.GetCallerIdentityInput{}
	result, err := svc.GetCallerIdentity(context, input)
	if err != nil {
		logrus.Fatal("Failed to get caller identity:", err)
	}
	logrus.Debugln("AWS STS GetCallerIdentity result:", result)

	retrievedStsRoleArn := *result.Arn
	// STS assumed role arn differs from IAM role arn
	// IAM arn:aws:iam::123456789000:role/example-role
	// STS arn:aws:sts::123456789000:assumed-role/example-role/example-username
	calculatedAssumedRoleArn := strings.Replace(strings.Replace(retrievedStsRoleArn, "sts", "iam", 1), "assumed-role", "role", 1)

	// AssumedRole should contain the RoleArn since the AssumedRole also contains the username a exact match won't work
	if !strings.Contains(calculatedAssumedRoleArn, roleArn) {
		logrus.Fatal("Login failed, role arn did not match with expected arn.")
	}
}

func CheckIfAwsConfigFileExists() {
	if _, err := os.Stat(getConfigFilePath()); os.IsNotExist(err) {
		logrus.Fatal("It looks like you have no AWS configuration file. Please run `aws configure` first. You can leave the access key fields empty.")
	}
	logrus.Debugln("AWS configuration file exists.")
}

func WriteCredentialFile(profile string, credentials *types.Credentials) {
	accessKeyId := *credentials.AccessKeyId
	secretAccessKey := *credentials.SecretAccessKey
	sessionToken := *credentials.SessionToken

	credentialFilePath := getCredentialFilePath()
	createCredentialsFileIfNotExists(credentialFilePath)

	cfg, err := ini.Load(credentialFilePath)
	if err != nil {
		logrus.Fatal("Failed to read credentials file:", err)
	}

	sec := cfg.Section(profile) // Auto-create if not exists
	createNewKeyInSection(sec, "aws_access_key_id", accessKeyId)
	createNewKeyInSection(sec, "aws_secret_access_key", secretAccessKey)
	createNewKeyInSection(sec, "aws_session_token", sessionToken)

	err = cfg.SaveTo(credentialFilePath)
	if err != nil {
		logrus.Fatal("Credentials could not be saved:  ", err)
	}
	logrus.Debugf("Credentials saved to '%s' under profile section: [%s]", credentialFilePath, profile)
}

func createNewKeyInSection(sec *ini.Section, key string, value string) {
	_, err := sec.NewKey(key, value)
	if err != nil {
		logrus.Fatal("Unable to create new section in config file.", err)
	}
}

func createCredentialsFileIfNotExists(credentialFilePath string) {
	file, err := os.OpenFile(credentialFilePath, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		logrus.Fatal("Unable to create AWS CLI credentials file.", err)
	}
	file.Close()
}

func getAwsCliPath() string {
	awsCliPath := getUserHomeDir() + string(os.PathSeparator) + ".aws" + string(os.PathSeparator)
	return awsCliPath
}

func getCredentialFilePath() string {
	credentialFilePath := getAwsCliPath() + "credentials"
	logrus.Debugln("Calculated AWS CLI credentials file path:", credentialFilePath)
	return credentialFilePath
}

func getConfigFilePath() string {
	configFilePath := getAwsCliPath() + "config"
	logrus.Debugln("Calculated AWS CLI config file path:", configFilePath)
	return configFilePath
}
