package aws_keyhub

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cli/browser"
	"github.com/sirupsen/logrus"
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
	AccessToken  string  `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
	Scope        string  `json:"scope"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
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
		if config.Keyhub.AllowInsecureTLS {
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal("Failed to read KeyHub authorize device response body", err)
	}
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal("Failed to read KeyHub login response body", err)
	}
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

	writeLoginToken(body)

	return result
}

func writeLoginToken(body []byte) {
	writeFile, err := os.Create("login.json")
	if err != nil {
		logrus.Fatal("Error creating login.json file:", err)
	}
	defer writeFile.Close()
	_, err = writeFile.Write(body)
	if err != nil {
		logrus.Fatal("Error writing to login.json file:", err)
	}
}

// TODO: Zorgen dat we andere response returnen indien het niet lukt.
func RefreshToken() LoginResponse {

	httpClient := getHTTPClient()
	config := getAwsKeyHubConfig()

	// TODO: get refresh token from secure storage? or..? u

	file, err := os.Open("login.json")
	if err != nil {
		logrus.Fatal("Error opening login.json file:", err)
	}
	defer file.Close()

	var loginResponse LoginResponse
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&loginResponse); err != nil {
		logrus.Fatal("Error decoding login.json file:", err)
	}

	if loginResponse.RefreshToken == nil {
		logrus.Fatal("Error, no refresh token found in login.json file")
	}

	tokenPath := "/login/oauth2/token"
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {*loginResponse.RefreshToken},
		"client_id":     {config.Keyhub.ClientId},
	}
	logrus.Debugln("KeyHub login POST formdata: ", data)

	resp, err := httpClient.PostForm(config.Keyhub.Url+tokenPath, data)
	if err != nil {
		logrus.Fatal("Failed to post form data to KeyHub token endpoint.", err)
	}
	logrus.Debugln("KeyHub login response body:", resp)

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal("Failed to read KeyHub login response body", err)
	}
	logrus.Debugln("KeyHub login response body:", string(body))

	if resp.StatusCode == 200 {
		logrus.Infoln("KeyHub refresh successful.")
	} else {
		logrus.Errorln("KeyHub refresh failed, unexpected response with HTTP status code", resp.StatusCode)
	}
	var result LoginResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to the go struct pointer
		logrus.Fatal("Error, cannot unmarshal JSON")
	}

	writeLoginToken(body)
	return result
}

func ExchangeToken(loginResponse LoginResponse) ExchangeResponse {
	config := getAwsKeyHubConfig()
	httpClient := getHTTPClient()

	exchangePath := "/login/oauth2/token"
	data := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {loginResponse.AccessToken},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:saml2"},
		"resource":             {config.Keyhub.AwsSamlClientId},
		"client_id":            {config.Keyhub.ClientId},
	}
	exchangeUrl := config.Keyhub.Url + exchangePath
	logrus.Debugln("KeyHub token exchange POST formdata:", data)

	resp, err := httpClient.PostForm(exchangeUrl, data)
	if err != nil {
		logrus.Fatal("Failed to post form data to KeyHub exchange endpoint.", err)
	}
	logrus.Debugln("KeyHub token exchange url:", exchangeUrl, " response:", resp)

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal("Failed to read KeyHub exchange response body", err)
	}
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
