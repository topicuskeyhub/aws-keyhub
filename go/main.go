package main

import (
	"container/list"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/jessevdk/go-flags"
	"github.com/zalando/go-keyring"
	"path"
	"strings"
	"sync"

	"log"
	"net/url"
	"os"
)

const serviceName = "aws-keyhub-go"

type Options struct {
	Configure bool   `short:"c" long:"configure" description:"Configure KeyHub url and credentials"`
	RoleArn   string `short:"r" long:"role-arn" description:"Automatically continue log-in with specified role ARN."`
}

func main() {
	var options Options

	var parser = flags.NewParser(&options, flags.Default)

	if _, err := parser.Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				os.Exit(0)
			}
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	if needsConfiguring(homedir) || options.Configure {
		configureAwsKeyhub(homedir)
	}
	keyhubConfig := readConfig(homedir)

	password, err := keyring.Get(serviceName, keyhubConfig.Keyhub.Username)
	if err == keyring.ErrNotFound {
		fmt.Println("No password found in native keyring, try reconfiguring using `aws-keyhub -c`")
		os.Exit(1)
	}

	u := launcher.New().
		UserDataDir(homedir + path.Join(".aws-keyhub-go", "browser")).
		MustLaunch()

	browser := rod.New().
		ControlURL(u).
		MustConnect()

	// Auto-close out-of-scope
	defer browser.MustClose()

	router := browser.HijackRequests()

	var wg sync.WaitGroup

	router.MustAdd("https://signin.aws.amazon.com/saml", func(ctx *rod.Hijack) {
		samlResponse := ctx.Request.Body()

		fmt.Println("Start met co-routine")
		wg.Add(1)
		go loginAws(&wg, samlResponse, &keyhubConfig, options.RoleArn)

		fmt.Println("klaar met co-routine")
		//ctx.Response.Fail(proto.NetworkErrorReasonAborted)
		// Cancel the request, this request should not complete
		err := router.Stop()
		if err != nil {
			panic(err)
		}
	})

	// Start al co-routine
	go router.Run()
	defer func(router *rod.HijackRouter) {
		err := router.Stop()
		if err != nil {

		}
	}(router)

	page := browser.MustPage(keyhubConfig.Keyhub.Url).MustWaitLoad()

	attempts := 0
	for {
		page.MustWaitLoad()

		if attempts >= 7 {
			fmt.Println("To many failed login attempts, maybe something is wrong with the username/password/2fa")
			os.Exit(1)
		}
		if usernamePassword2faLoop(page, keyhubConfig, password) {
			break
		}
		attempts += 1
	}
}

func usernamePassword2faLoop(page *rod.Page, config KeyhubConfigFile, password string, twofactor string) bool {
	var result = false
	fmt.Println("Wachten op element")
	page.Race().Element("input[name=\"username\"]").MustHandle(func(e *rod.Element) {
		fmt.Println("username gevonden")
		e.MustInput(config.Keyhub.Username)
		page.Keyboard.MustPress(input.Enter)
		fmt.Println("Klaar met username")
	}).Element("input[name=\"password\"]").MustHandle(func(e *rod.Element) {
		fmt.Println("wachtwoord gevonden")
		e.MustInput(password)
		page.Keyboard.MustPress(input.Enter)
		fmt.Println("Klaar met password")
	}).Element("input[name=\"token\"]").MustHandle(func(e *rod.Element) {

		fmt.Println("2fa gevonden")
		if twofactor != "" {
			return
		}
		fmt.Println("2fa invullen")
		go ask2fA()
		e.MustInput(twofactor)
		page.Keyboard.MustPress(input.Enter)
		fmt.Println("Klaar met 2fa")
	}).MustDo()

	fmt.Println("Klaar met race")

	return result
}


var isAsking2fa = false

func ask2fA() string {
	isAsking2fa = true
	// the questions to ask
	var twofactor string
	err := survey.AskOne(&survey.Input{Message: "KeyHub verification code (2FA)"}, &twofactor)
	if err != nil {
		panic(err)
	}
	isAsking2fa = false
	return twofactor
}

func getArnDescriptionForArn(groups *list.List, roleArn string) *ArnDescription {
	if roleArn == "" {
		return nil
	}
	for e := groups.Front(); e != nil; e = e.Next() {
		if e.Value.(*ArnDescription).Arn == roleArn {
			return e.Value.(*ArnDescription)
		}
	}
	return nil
}

func loginAws(wg *sync.WaitGroup, response string, keyhubConfig *KeyhubConfigFile, roleArn string) {
	defer wg.Done()
	fmt.Println("Saml response ontvangen")
	encoded := strings.Replace(response, "SAMLResponse=", "", 1)
	queryUnescaped, err := url.QueryUnescape(encoded)
	if err != nil {
		panic(err)
	}
	b64decoded, err := base64.StdEncoding.DecodeString(queryUnescaped)
	if err != nil {
		panic(err)
	}
	keyhubGroups := getAvailableKeyhubGroupsFromSaml(b64decoded)

	preselectedArnAvailable := getArnDescriptionForArn(keyhubGroups, roleArn) != nil

	var selectedGroupArn string
	if !preselectedArnAvailable {
		if roleArn != "" {
			log.Println(fmt.Sprintf("Specified arn '%s' is not availabile", roleArn))
		}
		var options []string
		for e := keyhubGroups.Front(); e != nil; e = e.Next() {
			options = append(options, e.Value.(*ArnDescription).Description)
		}
		err = survey.AskOne(&survey.Select{
			Message: "Choose a role",
			Options: options,
		}, &selectedGroupArn)
		if err != nil {
			panic(err)
		}
	} else {
		selectedGroupArn = roleArn
	}

	selectedGroup := getArnDescriptionForArn(keyhubGroups, selectedGroupArn)

	if selectedGroup == nil {
		log.Panic("Failed to select role")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	client := sts.NewFromConfig(cfg)
	params := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int32(keyhubConfig.Aws.AssumeDuration),
		PrincipalArn:    aws.String(selectedGroup.SamlProvider),
		RoleArn:         aws.String(selectedGroup.Arn),
		SAMLAssertion:   aws.String(queryUnescaped),
	}
	stsResponse, err := client.AssumeRoleWithSAML(context.TODO(), params)
	if err != nil {
		panic(err)
	}

	writeAwsConfig(stsResponse)
	fmt.Println("Successfully logged in, use the profile `keyhub`. (export AWS_PROFILE=keyhub / set AWS_PROFILE=keyhub / $env:AWS_PROFILE='keyhub')")
	os.Exit(0)
}