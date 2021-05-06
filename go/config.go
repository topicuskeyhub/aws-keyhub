package main

import (
	"encoding/json"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/alyu/configparser"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zalando/go-keyring"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
)

type KeyhubConfigFile struct {
	Keyhub KeyhubConfig    `json:"keyhub"`
	Aws    KeyhubAwsConfig `json:"aws"`
}

type KeyhubConfig struct {
	Username string `json:"username"`
	Url      string `json:"url"`
}

type KeyhubAwsConfig struct {
	AssumeDuration int32 `json:"assumeDuration"`
}

func needsConfiguring(homedir string) bool {
	if _, err := os.Stat(keyHubConfigFile(homedir)); os.IsNotExist(err) {
		return true
	}
	return false
}

func configureAwsKeyhub(homedir string) {
	fmt.Println("aws-keyhub setup wizard, please provide the following the information:")
	var questions = []*survey.Question{
		{
			Name:     "username",
			Prompt:   &survey.Input{Message: "KeyHub Username"},
			Validate: survey.Required,
		},
		{
			Name:     "password",
			Prompt:   &survey.Password{Message: "KeyHub or AD password (depending on your password synchronization settings)"},
			Validate: survey.Required,
		},
		{
			Name:     "keyHubUrl",
			Prompt:   &survey.Input{Message: "KeyHub url", Default: "https://keyhub.domain.tld/login/initiate?client=urn:amazon:webservices"},
			Validate: survey.Required,
		},
		{
			Name:     "assumeDuration",
			Prompt:   &survey.Input{Message: "AWS assume role duration (in seconds, max value is 43200) ", Default: "43200"},
			Validate: survey.Required,
		},
	}
	answers := struct {
		Username       string
		Password       string
		KeyHubUrl      string
		AssumeDuration int32
	}{}

	err := survey.Ask(questions, &answers)
	if err != nil {
		panic(err)
	}

	config := KeyhubConfigFile{
		Aws: KeyhubAwsConfig{
			AssumeDuration: answers.AssumeDuration,
		},
		Keyhub: KeyhubConfig{
			Username: answers.Username,
			Url:      answers.KeyHubUrl,
		},
	}

	writeConfig(homedir, &config)
	writePassword(answers.Username, answers.Password)
}

func keyHubConfigFile(homedir string) string {
	return path.Join(homedir, ".aws-keyhub-go", "config.json")
}

func readConfig(homedir string) KeyhubConfigFile {
	var configFile KeyhubConfigFile

	dat, err := ioutil.ReadFile(keyHubConfigFile(homedir))
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(dat, &configFile)
	if err != nil {
		panic(err)
	}
	return configFile
}

func writeConfig(homedir string, config *KeyhubConfigFile) {
	res, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		panic(res)
	}
	err = ioutil.WriteFile(keyHubConfigFile(homedir), res, 0600)
	if err != nil {
		panic(err)
	}
	log.Println("Updated configfile " + keyHubConfigFile(homedir))
}

func writePassword(username string, password string) {
	err := keyring.Set(serviceName, username, password)
	if err != nil {
		log.Println("Failed to write password to keyring, maybe a permission is required?")
		if runtime.GOOS == "linux" {
			fmt.Println("Please make sure gnome-keyring and libsecret or equivalent is installed")
		}
		panic(err)
	}
	log.Println("Successfully updated password in keyring")
}



func writeAwsConfig(response *sts.AssumeRoleWithSAMLOutput) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	credentialsFile, err := configparser.Read(homedir + "/.aws/credentials")
	if err != nil {
		panic(err)
	}

	section, err := credentialsFile.Section("keyhub")
	if section != nil {
		section.SetValueFor("aws_access_key_id", *response.Credentials.AccessKeyId)
		section.SetValueFor("aws_secret_access_key", *response.Credentials.SecretAccessKey)
		section.SetValueFor("aws_session_token", *response.Credentials.SessionToken)
	}

	err = configparser.Save(credentialsFile, homedir+"/.aws/credentials")
}

