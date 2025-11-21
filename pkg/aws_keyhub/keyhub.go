package aws_keyhub

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/cli/browser"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

const MaxPollAttempts = 24
const RefreshTokenClockSkewSeconds = 30

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

type KeyhubErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type RefreshTokenFile struct {
	RefreshToken string    `json:"refresh_token"`
	ExpireDate   time.Time `json:"expire_date"`
}

type TokenExchangeResponse struct {
	AccessToken     string  `json:"access_token"`
	RefreshToken    *string `json:"refresh_token"`
	Scope           string  `json:"scope"`
	TokenType       string  `json:"token_type"`
	IssuedTokenType string  `json:"issued_token_type"`
	ExpiresIn       int     `json:"expires_in"`
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

func authorizeDevice() AuthorizeDeviceResponse {
	config := getAwsKeyHubConfig()
	httpClient := getHTTPClient()

	authorizeDevicePath := "/login/oauth2/authorizedevice"
	data := url.Values{
		"resource":  {config.Keyhub.AwsSamlClientId},
		"scope":     {"profile"},
		"client_id": {config.Keyhub.ClientId},
	}
	logrus.Debugln("KeyHub authorize device POST formdata: ", data)
	resp, err := httpClient.PostForm(config.Keyhub.Url+authorizeDevicePath, data)
	if err != nil {
		logrus.Fatal("Failed to post form data to KeyHub authorize device endpoint.", err)
	}

	if resp.StatusCode != 200 {
		handleUnexpectedResponseCodeResponse(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal("Failed to read KeyHub authorize device response body", err)
	}
	logrus.Debugln("KeyHub authorize device response body:", string(body))

	var result AuthorizeDeviceResponse
	if err := json.Unmarshal(body, &result); err != nil {
		logrus.Fatal("Device authorization failed; could not unmarshal JSON")
	}

	logrus.Debugln("KeyHub authorize device received confirmation code:", result.UserCode)
	browser.OpenURL(result.VerificationUriComplete)
	logrus.Infoln("If your browser did not open, please visit this url:", result.VerificationUriComplete)

	return result
}

func DoLogin() TokenExchangeResponse {
	refreshTokenFile := readRefreshToken()
	var tokenExchangeResponse *TokenExchangeResponse
	if refreshTokenFile != nil && isAccessTokenValid(*refreshTokenFile) {
		logrus.Infoln("Attempting KeyHub login using refresh token.")
		tokenExchangeResponse = getAccessTokenWithRefreshToken(*refreshTokenFile)
	} else if refreshTokenFile != nil {
		removeInvalidOrExpiredRefreshTokenFile()
	}

	logrus.Debugln("TokenExchangeResponse from refresh token:", tokenExchangeResponse)

	if tokenExchangeResponse != nil {
		return *tokenExchangeResponse
	}
	authorizeDeviceResponse := authorizeDevice()
	return pollForAccessToken(authorizeDeviceResponse, 0)
}

func pollForAccessToken(authorizeDeviceresponse AuthorizeDeviceResponse, noOfTimesPolled int) TokenExchangeResponse {
	noOfTimesPolled++
	if noOfTimesPolled > MaxPollAttempts {
		logrus.Fatal("Keyhub login failed. Authorization request was not accepted in a timely manner.")
	}
	config := getAwsKeyHubConfig()

	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {authorizeDeviceresponse.DeviceCode},
		"client_id":   {config.Keyhub.ClientId},
	}
	resp := submitTokenExchange(data)

	switch resp.StatusCode {
	case 200:
		return handleTokenExchangeSuccessResponse(resp, true)
	case 400:
		errorResponse := handleErrorResponse(resp)
		if errorResponse.Error == "authorization_pending" {
			logrus.Debugf("Waiting %d seconds for user to authorize device...", authorizeDeviceresponse.Interval)
			time.Sleep(time.Duration(authorizeDeviceresponse.Interval) * time.Second)
			return pollForAccessToken(authorizeDeviceresponse, noOfTimesPolled)
		} else {
			logrus.Fatalf("KeyHub login failed: %s", errorResponse.ErrorDescription)
		}
	default:
		handleUnexpectedResponseCodeResponse(resp)
	}
	return TokenExchangeResponse{}
}

func getAccessTokenWithRefreshToken(refreshTokenFile RefreshTokenFile) *TokenExchangeResponse {
	config := getAwsKeyHubConfig()

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenFile.RefreshToken},
		"client_id":     {config.Keyhub.ClientId},
	}
	resp := submitTokenExchange(data)

	switch resp.StatusCode {
	case 200:
		logrus.Infoln("KeyHub login using token refresh successful.")
		resp := handleTokenExchangeSuccessResponse(resp, true)
		return &resp
	case 400:
		defer removeInvalidOrExpiredRefreshTokenFile()
		errorResponse := handleErrorResponse(resp)
		logrus.Errorf("KeyHub token refresh failed: %s", errorResponse.ErrorDescription)
		return nil
	default:
		defer removeInvalidOrExpiredRefreshTokenFile()
		handleUnexpectedResponseCodeResponse(resp)
	}
	return nil
}

func ExchangeToken(tokenExchangeResponse TokenExchangeResponse) TokenExchangeResponse {
	config := getAwsKeyHubConfig()
	data := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {tokenExchangeResponse.AccessToken},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:saml2"},
		"resource":             {config.Keyhub.AwsSamlClientId},
		"client_id":            {config.Keyhub.ClientId},
	}
	resp := submitTokenExchange(data)

	switch resp.StatusCode {
	case 200:
		logrus.Infoln("KeyHub token exchange successful.")
		return handleTokenExchangeSuccessResponse(resp, false)
	default:
		handleUnexpectedResponseCodeResponse(resp)
	}
	return TokenExchangeResponse{}
}

func submitTokenExchange(data url.Values) *http.Response {
	httpClient := getHTTPClient()
	config := getAwsKeyHubConfig()

	tokenPath := "/login/oauth2/token"
	logrus.Debugln("KeyHub token exchange POST formdata: ", data)
	resp, err := httpClient.PostForm(config.Keyhub.Url+tokenPath, data)
	if err != nil {
		logrus.Fatal("Failed to post form data to KeyHub token endpoint.", err)
	}
	logrus.Debugln("KeyHub token exchange response:", resp)
	return resp
}

func readRefreshToken() *RefreshTokenFile {
	filePath := GetAwsKeyHubRefreshTokenPath()
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var refreshTokenFile RefreshTokenFile
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&refreshTokenFile); err != nil {
		logrus.Fatal("Error decoding refresh-token.json file:", err)
	}
	return &refreshTokenFile
}

func isAccessTokenValid(refreshTokenFile RefreshTokenFile) bool {
	if refreshTokenFile.RefreshToken == "" {
		return false
	} else if refreshTokenFile.ExpireDate.Add(-RefreshTokenClockSkewSeconds * time.Second).Before(time.Now()) {
		return false
	}

	return true
}
func handleTokenExchangeSuccessResponse(resp *http.Response, shouldStoreRefreshToken bool) TokenExchangeResponse {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatal("Failed to read KeyHub token exchange response body", err)
	}
	logrus.Debugln("KeyHub token exchange response body:", string(body))

	var result TokenExchangeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		logrus.Fatal("KeyHub token exchange failed; could not unmarshal JSON")
	}

	if shouldStoreRefreshToken && result.RefreshToken != nil {
		storeRefreshToken(result)
	}
	return result
}

func handleUnexpectedResponseCodeResponse(resp *http.Response) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorln("Failed to read keyhub response body:", err)
	}
	logrus.Errorln("KeyHub returned unexpected HTTP status code", resp.StatusCode)
	logrus.Fatal("Received HTTP response body:", string(body))
}

func handleErrorResponse(resp *http.Response) *KeyhubErrorResponse {
	var errorResponse KeyhubErrorResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorln("Failed to read KeyHub error response:", err)
	}
	if err := json.Unmarshal(body, &errorResponse); err != nil {
		logrus.Errorln("Failed to unmarshal Keyhub error response:", err)
	}
	return &errorResponse
}

func storeRefreshToken(tokenExchangeResponse TokenExchangeResponse) {
	logrus.Debugln("Storing refresh token to file.")
	filePath := GetAwsKeyHubRefreshTokenPath()
	writeFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		logrus.Fatalf("Error creating %s file: %s", filePath, err)
	}
	defer writeFile.Close()

	refreshTokenFile := RefreshTokenFile{
		RefreshToken: *tokenExchangeResponse.RefreshToken,
		ExpireDate:   determineRefreshTokenExpireDate(tokenExchangeResponse),
	}

	jsonBytes, err := json.Marshal(refreshTokenFile)
	if err != nil {
		logrus.Fatal("Error marshaling refresh token to JSON:", err)
	}
	_, err = writeFile.Write(jsonBytes)
	if err != nil {
		logrus.Fatalf("Error writing to %s file: %s", filePath, err)
	}
	logrus.Debugln("Wrote refresh token to file at", filePath)
}

// there is no field (yet) for refresh token expiration in the token exchange response, this is a best-effort attempt to determine it
func determineRefreshTokenExpireDate(tokenExchangeResponse TokenExchangeResponse) time.Time {
	var fallback = time.Now().Add(time.Duration(tokenExchangeResponse.ExpiresIn) * time.Second)
	if tokenExchangeResponse.RefreshToken == nil || *tokenExchangeResponse.RefreshToken == "" {
		logrus.Debugln("No refresh token present; using token expiration as fallback.")
		return fallback
	}
	token, _, err := new(jwt.Parser).ParseUnverified(*tokenExchangeResponse.RefreshToken, jwt.MapClaims{})
	if err == nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if exp, ok := claims["exp"].(float64); ok {
				return time.Unix(int64(exp), 0)
			}
		}
	}
	logrus.Debugln("Unable to parse refresh token; using token expiration as fallback.")
	return fallback
}

func removeInvalidOrExpiredRefreshTokenFile() {
	filePath := GetAwsKeyHubRefreshTokenPath()
	err := os.Remove(filePath)
	if err != nil {
		logrus.Errorln("Error removing refresh token file:", err)
	} else {
		logrus.Debugln("Removed invalid or expired refresh token file.")
	}
}
