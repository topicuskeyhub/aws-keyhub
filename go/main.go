package main

import (
	"bytes"
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/alyu/configparser"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/zalando/go-keyring"

	"io/ioutil"
	"log"
	"net/url"
	"os"
	strings "strings"
	"time"
)

const serviceName = "aws-keyhub-go"

func main() {

	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	keyhubConfig := readConfig(homedir)

	password, err := keyring.Get(serviceName, keyhubConfig.Keyhub.Username)
	if err == keyring.ErrNotFound {
		password := askPassword()
		err := keyring.Set(serviceName, keyhubConfig.Keyhub.Username, password)
		if err != nil {
			panic(err)
		}
	}
	u := launcher.New().
		UserDataDir(homedir + "/.aws-keyhub-go/browser/").
		MustLaunch()

	browser := rod.New().
		ControlURL(u).
		MustConnect()

	router := browser.HijackRequests()

	router.MustAdd("https://signin.aws.amazon.com/saml", func(ctx *rod.Hijack) {
		samlResponse := ctx.Request.Body()
		// Cancel the request, this request should not complete
		ctx.Response.Fail(proto.NetworkErrorReasonAborted)
		loginAws(samlResponse)
		browser.MustClose()
	})

	go router.Run()

	page := browser.MustPage(keyhubConfig.Keyhub.Url).MustWaitLoad()

	attemts := 0
	for {
		if attemts >= 7 {
			panic("teveel mislukte pogingen.. mogelijk is er iets mis met gebruikersnaam/wachtwoord/2fa :(")
		}
		if usernamePassword2faLoop(page, keyhubConfig, password) {
			break
		}
		attemts += 1
	}

	time.Sleep(time.Hour)
}

func readConfig(homedir string) KeyhubConfigFile {
	var configFile KeyhubConfigFile

	dat, err := ioutil.ReadFile(homedir + "/.aws-keyhub/config.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(dat, &configFile)
	if err != nil {
		panic(err)
	}
	return configFile
}

type KeyhubConfigFile struct {
	Keyhub KeyhubConfig `json:"keyhub"`
}

type KeyhubConfig struct {
	Username string `json:"username"`
	Url      string `json:"url"`
}

func usernamePassword2faLoop(page *rod.Page, config KeyhubConfigFile, password string) bool {
	var klaar = false

	page.Race().Element("input[name=\"username\"]").MustHandle(func(e *rod.Element) {
		var username = config.Keyhub.Username
		// print the username after successful login
		fmt.Println(*e.MustInput(username))
		page.Keyboard.MustPress(input.Enter)
	}).Element("input[name=\"password\"]").MustHandle(func(e *rod.Element) {
		e.MustInput(password)
		page.Keyboard.MustPress(input.Enter)
	}).Element("input[name=\"token\"]").MustHandle(func(e *rod.Element) {
		var twofactor = ask2fA()
		e.MustInput(twofactor)
		page.Keyboard.MustPress(input.Enter)
		klaar = true
	}).MustDo()

	return klaar
}

func askUsername() string {
	// the questions to ask
	var twofactor string
	err := survey.AskOne(&survey.Input{Message: "Wat is je gebruikersnaam"}, &twofactor)
	if err != nil {
		panic(err)
	}
	return twofactor
}

func ask2fA() string {
	// the questions to ask
	var twofactor string
	err := survey.AskOne(&survey.Password{Message: "KeyHub verification code (2FA)"}, &twofactor)
	if err != nil {
		panic(err)
	}
	return twofactor
}

func askPassword() string {
	// the questions to ask
	var password string
	err := survey.AskOne(&survey.Password{Message: "Wat is je wachtwoord"}, &password)
	if err != nil {
		panic(err)
	}
	return password
}

func loginAws(response string) {
	encoded := strings.Replace(response, "SAMLResponse=", "", 1)
	queryUnescaped, err := url.QueryUnescape(encoded)
	if err != nil {
		panic(err)
	}
	b64decoded, err := base64.StdEncoding.DecodeString(queryUnescaped)
	if err != nil {
		panic(err)
	}
	groepen := haalGroepenUitSaml(b64decoded)

	var options []string

	for e := groepen.Front(); e != nil; e = e.Next() {
		options = append(options, e.Value.(ArnDescription).Description)
	}

	var selectedGroupName string
	err = survey.AskOne(&survey.Select{
		Message: "Kies een groep:",
		Options: options,
	}, &selectedGroupName)

	if err != nil {
		panic(err)
	}

	var selectedGroup ArnDescription

	for e := groepen.Front(); e != nil; e = e.Next() {
		a := e.Value.(ArnDescription)
		if a.Description == selectedGroupName {
			selectedGroup = a
		}
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	client := sts.NewFromConfig(cfg)
	params := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int32(3600),
		PrincipalArn:    aws.String(selectedGroup.SamlProvider),
		RoleArn:         aws.String(selectedGroup.Arn),
		SAMLAssertion:   aws.String(queryUnescaped),
	}
	stsResponse, err := client.AssumeRoleWithSAML(context.TODO(), params)
	if err != nil {
		panic(err)
	}

	writeAwsConfig(stsResponse)
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

	err = configparser.Save(credentialsFile, homedir + "/.aws/credentials")
}

type Node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",attr"`
	Content []byte     `xml:",innerxml"`
	Nodes   []Node     `xml:",any"`
}

func haalGroepenUitSaml(decoded []byte) *list.List {
	var groups = list.New()

	buf := bytes.NewBuffer(decoded)
	dec := xml.NewDecoder(buf)

	var n Node
	err := dec.Decode(&n)
	if err != nil {
		panic(err)
	}
	walk([]Node{n}, func(n Node) bool {
		if n.XMLName.Local == "Attribute" {
			if "https://github.com/topicuskeyhub/aws-keyhub/groups" == n.Attrs[0].Value {
				groups = processKeyhubGroups(n)
				return true
			}
		}
		return true
	})
	return groups
}

type ArnDescription struct {
	Description  string
	Arn          string
	SamlProvider string
}

func processKeyhubGroups(n Node) *list.List {
	result := list.New()

	for _, rek := range n.Nodes {
		var arnDescription ArnDescription
		err := json.Unmarshal(rek.Content, &arnDescription)
		if err != nil {
			panic(err)
		}
		splitParts := strings.Split(arnDescription.Arn, ",")
		arnDescription.Arn = splitParts[0]
		arnDescription.SamlProvider = splitParts[1]
		result.PushBack(arnDescription)

	}
	return result
}

func walk(nodes []Node, f func(Node) bool) {
	for _, n := range nodes {
		if f(n) {
			walk(n.Nodes, f)
		}
	}
}

func (n *Node) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	n.Attrs = start.Attr
	type node Node

	return d.DecodeElement((*node)(n), &start)
}
