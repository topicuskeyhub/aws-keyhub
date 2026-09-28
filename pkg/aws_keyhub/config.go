package aws_keyhub

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"

	"path/filepath"
	"sync"

	"github.com/charmbracelet/huh"
	"github.com/sirupsen/logrus"
)

var awsKeyHubConfigFile KeyhubConfigFile
var doOnceReadAwsKeyHubConfig sync.Once

func ConfigureAwsKeyhub() {
	logrus.Println("aws-keyhub configuration wizard, please provide the following the information:")
	var keyHubUrl, keyHubClientId, keyHubAwsSamlClientId string
	assumeDuration := "43200"

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("KeyHub url (e.g. https://keyhub.domain.tld)").
				Validate(required).
				Value(&keyHubUrl),
			huh.NewInput().
				Title("KeyHub aws-keyhub client id (e.g. 00000000-0000-0000-0000-000000000000)").
				Validate(required).
				Value(&keyHubClientId),
			huh.NewInput().
				Title("KeyHub Resource URN for the AWS SAML connection (e.g. urn:tkh-clientid:urn:amazon:webservices)").
				Validate(required).
				Value(&keyHubAwsSamlClientId),
			huh.NewInput().
				Title("AWS assume role duration (in seconds, maximum value is 43200)").
				Validate(validateAssumeDuration).
				Value(&assumeDuration),
		),
	)

	err := form.Run()
	if err != nil {
		logrus.Fatal("Failed to prompt user for configuration settings.", err)
	}

	duration, _ := strconv.ParseInt(strings.TrimSpace(assumeDuration), 10, 32)

	config := KeyhubConfigFile{
		Aws: KeyhubAwsConfig{
			AssumeDuration: int32(duration),
		},
		Keyhub: KeyhubConfig{
			Url:             keyHubUrl,
			ClientId:        keyHubClientId,
			AwsSamlClientId: keyHubAwsSamlClientId,
		},
	}

	logrus.Debugln(config)
	writeConfig(config)
}

func required(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value is required")
	}
	return nil
}

func validateAssumeDuration(value string) error {
	duration, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return errors.New("value must be a number")
	}
	if duration < 900 || duration > 43200 {
		return errors.New("value must be between 900 and 43200")
	}
	return nil
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
	AssumeDuration int32 `json:"assumeDuration"`
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

func GetAwsKeyHubRefreshTokenPath() string {
	return filepath.Join(getAwsKeyHubConfigDirectory(), "refresh-token.json")
}

func getAwsKeyHubConfig() KeyhubConfigFile {
	doOnceReadAwsKeyHubConfig.Do(func() {
		dat, err := os.ReadFile(getAwsKeyHubConfigFilePath())
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
	err = os.WriteFile(getAwsKeyHubConfigFilePath(), res, 0600)
	if err != nil {
		logrus.Fatal("Failed to write aws-keyhub configuration file.", err)
	}
	logrus.Debugln("Wrote aws-keyhub configuration file at", getAwsKeyHubConfigFilePath())
}
