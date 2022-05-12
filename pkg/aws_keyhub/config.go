package aws_keyhub

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/AlecAivazis/survey/v2"
	"github.com/sirupsen/logrus"
)

var awsKeyHubConfigFile KeyhubConfigFile
var doOnceReadAwsKeyHubConfig sync.Once

func ConfigureAwsKeyhub() {
	logrus.Println("aws-keyhub configuration wizard, please provide the following the information:")
	var questions = []*survey.Question{
		{
			Name:     "keyHubUrl",
			Prompt:   &survey.Input{Message: "KeyHub url (e.g. https://keyhub.domain.tld)"},
			Validate: survey.Required,
		},
		{
			Name:     "keyHubClientId",
			Prompt:   &survey.Input{Message: "KeyHub aws-keyhub client id (e.g. 00000000-0000-0000-0000-000000000000"},
			Validate: survey.Required,
		},
		{
			Name:     "keyHubAwsSamlClientId",
			Prompt:   &survey.Input{Message: "KeyHub Resource URN for the AWS SAML connection (e.g. urn:tkh-clientid:urn:amazon:webservices)"},
			Validate: survey.Required,
		},
		{
			Name:     "assumeDuration",
			Prompt:   &survey.Input{Message: "AWS assume role duration (in seconds, maximum value is 43200) ", Default: "43200"},
			Validate: survey.Required,
		},
	}
	answers := struct {
		KeyHubUrl             string
		KeyHubClientId        string
		KeyHubAwsSamlClientId string
		AssumeDuration        int64
	}{}

	err := survey.Ask(questions, &answers)
	if err != nil {
		logrus.Fatal("Failed to prompt user for configuration settings.", err)
	}

	config := KeyhubConfigFile{
		Aws: KeyhubAwsConfig{
			AssumeDuration: answers.AssumeDuration,
		},
		Keyhub: KeyhubConfig{
			Url:             answers.KeyHubUrl,
			ClientId:        answers.KeyHubClientId,
			AwsSamlClientId: answers.KeyHubAwsSamlClientId,
		},
	}

	logrus.Debugln(config)
	writeConfig(config)
}

type KeyhubConfigFile struct {
	Keyhub KeyhubConfig    `json:"keyhub"`
	Aws    KeyhubAwsConfig `json:"aws"`
}

type KeyhubConfig struct {
	Url              string `json:"url"`
	ClientId         string `json:"clientId"`
	AwsSamlClientId  string `json:"awsSamlClientId"`
	AllowInsecureTLS bool   `json:"allowInsecureTLS"` // We do not prompt for this flag, but it is configurable for development purposes.
}

type KeyhubAwsConfig struct {
	AssumeDuration int64 `json:"assumeDuration"`
}

func CheckIfAwsKeyHubConfigFileExists() {
	if _, err := os.Stat(getAwsKeyHubConfigFilePath()); os.IsNotExist(err) {
		logrus.Fatal("It looks like you have no aws-keyhub configuration file. Please run `aws-keyhub configure` first.")
	}
	logrus.Debugln("aws-keyhub configuration file exists.")
}

func AssureAwsKeyHubConfigDirectoryExists() {
	configDirectory := getAwsKeyHubConfigDirectory()

	logContext := logrus.WithFields(logrus.Fields{
		"directory": configDirectory,
	})
	if _, err := os.Stat(configDirectory); os.IsNotExist(err) {
		err = os.Mkdir(configDirectory, 0700)
		if err != nil {
			logContext.Fatalln("Failed to create config directory", err)
		}
		logContext.Debugln("Config directory created")
		return
	}
	logContext.Debugln("Config directory already exists")
}

func getAwsKeyHubConfigDirectory() string {
	return filepath.Join(getUserHomeDir(), ".aws-keyhub")
}

func getAwsKeyHubConfigFilePath() string {
	return filepath.Join(getAwsKeyHubConfigDirectory(), "config-v2.json")
}

func getAwsKeyHubConfig() KeyhubConfigFile {
	doOnceReadAwsKeyHubConfig.Do(func() {
		dat, err := ioutil.ReadFile(getAwsKeyHubConfigFilePath())
		if err != nil {
			logrus.Fatal("Failed to read aws-keyhub configuration file.", err)
		}
		err = json.Unmarshal(dat, &awsKeyHubConfigFile)
		if err != nil {
			logrus.Fatal("Failed to unmarshal aws-keyhub configuration file.", err)
		}
		logrus.Debugln("Read aws-keyhub configuration file", awsKeyHubConfigFile)
	})

	return awsKeyHubConfigFile
}

func writeConfig(config KeyhubConfigFile) {
	res, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		logrus.Fatal("Failed to marshal aws-keyhub configuration file.", err)
	}
	err = ioutil.WriteFile(getAwsKeyHubConfigFilePath(), res, 0600)
	if err != nil {
		logrus.Fatal("Failed to write aws-keyhub configuration file.", err)
	}
	logrus.Debugln("Wrote aws-keyhub configuration file at", getAwsKeyHubConfigFilePath())
}
