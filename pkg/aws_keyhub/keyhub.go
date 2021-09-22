package aws_keyhub

import (
	"crypto/tls"
	"encoding/json"
	"github.com/pkg/browser"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var doOnceHTTPClient sync.Once
var httpClient http.Client

type AuthorizeDeviceResponse struct {
	UserCode                string `json:"user_code"`
	DeviceCode              string `json:"device_code"`
	Interval                int    `json:"interval"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	VerificationUri         string `json:"verification_uri"`
	ExpiresIn               int    `json:"expires_in"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type ExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	IssuedTokenType string `json:"issued_token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

func getHTTPClient() http.Client {
	config := getAwsKeyHubConfig()
	doOnceHTTPClient.Do(func() {
		logrus.Debugln("Initializing HTTP Client for further usage.")
		httpClient = http.Client{Timeout: time.Duration(20) * time.Second}
		if config.Keyhub.AllowInsecureTLS == true {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	})

	return httpClient
}

func AuthorizeDevice() AuthorizeDeviceResponse {
	config := getAwsKeyHubConfig()
	httpClient := getHTTPClient()

	authorizeDevicePath := "/login/oauth2/authorizedevice"
	data := url.Values{
		"resource":  {config.Keyhub.AwsSamlClientId},
		"scope":     {"profile"},
		"client_id": {config.Keyhub.ClientId},
	}

	resp, err := httpClient.PostForm(config.Keyhub.Url+authorizeDevicePath, data)
	if err != nil {
		logrus.Fatal("Failed to post form data to KeyHub authorize device endpoint.", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	logrus.Debugln("KeyHub authorize device response body:", string(body))

	var result AuthorizeDeviceResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to the go struct pointer
		logrus.Fatal("Cannot unmarshal JSON")
	}

	logrus.Debugln("KeyHub authorize device received confirmation code:", result.UserCode)
	browser.OpenURL(result.VerificationUriComplete)
	logrus.Infoln("If your browser did not open, please visit this url:", result.VerificationUriComplete)

	return result
}

func PollForAccessToken(authorizeDeviceresponse AuthorizeDeviceResponse, noOfTimesPolled int) LoginResponse {
	noOfTimesPolled++
	if noOfTimesPolled > 24 {
		logrus.Fatal("Keyhub login failed. Authorization request was not accepted in a timely manner.")
	}

	httpClient := getHTTPClient()
	config := getAwsKeyHubConfig()

	tokenPath := "/login/oauth2/token"
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {authorizeDeviceresponse.DeviceCode},
		"client_id":   {config.Keyhub.ClientId},
	}
	logrus.Debugln("KeyHub login POST formdata: ", data)

	resp, err := httpClient.PostForm(config.Keyhub.Url+tokenPath, data)
	if err != nil {
		logrus.Fatal("Failed to post form data to KeyHub token endpoint.", err)
	}
	logrus.Debugln("KeyHub login response body:", resp)

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	logrus.Debugln("KeyHub login response body:", string(body))

	if resp.StatusCode == 200 {
		logrus.Infoln("KeyHub login successful.")
	} else if resp.StatusCode == 400 && strings.Contains(strings.ToLower(string(body)), "authorization pending") {
		logrus.Debugln("KeyHub login polling request gave 400 statuscode and authorization pending retrying in 5 seconds...")
		time.Sleep(time.Duration(authorizeDeviceresponse.Interval) * time.Second)
		return PollForAccessToken(authorizeDeviceresponse, noOfTimesPolled)
	} else {
		logrus.Errorln("KeyHub login failed, unexpected response with HTTP status code", resp.StatusCode)
		logrus.Fatal("Received HTTP response body:", resp.Body)
	}

	var result LoginResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to the go struct pointer
		logrus.Fatal("Error, cannot unmarshal JSON")
	}

	return result
}

func ExchangeToken(loginResponse LoginResponse) ExchangeResponse {
	config := getAwsKeyHubConfig()
	httpClient := getHTTPClient()

	exchangePath := "/login/oauth2/exchange"
	data := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":      {loginResponse.AccessToken},
		"resource":           {config.Keyhub.AwsSamlClientId},
	}
	logrus.Debugln("KeyHub token exchange POST formdata:", data)

	resp, err := httpClient.PostForm(config.Keyhub.Url+exchangePath, data)
	if err != nil {
		logrus.Fatal("Failed to post form data to KeyHub exchange endpoint.", err)
	}
	logrus.Debugln("KeyHub token exchange response:", resp)

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	logrus.Debugln("KeyHub token exchange response body:", string(body))

	if resp.StatusCode == 200 {
		logrus.Infoln("KeyHub token exchange successful.")
	} else {
		logrus.Errorln("Unexpected response with HTTP statuscode ", resp.StatusCode, " received from KeyHub.")
		logrus.Fatal("Received HTTP response body:", resp.Body)
	}

	var result ExchangeResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to the go struct pointer
		logrus.Fatal("Error, cannot unmarshal JSON token exchange response:", err)
	}

	return result
}
