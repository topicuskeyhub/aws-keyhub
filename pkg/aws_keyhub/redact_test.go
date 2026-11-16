package aws_keyhub

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

const secret = "super-secret-token-value"

func TestRedactFormData(t *testing.T) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {secret},
		"subject_token": {secret},
		"device_code":   {secret},
		"client_id":     {"my-client"},
	}

	redacted := redactFormData(data)

	if out := fmt.Sprint(redacted); strings.Contains(out, secret) {
		t.Errorf("redacted form data still contains secret: %s", out)
	}
	if redacted.Get("client_id") != "my-client" || redacted.Get("grant_type") != "refresh_token" {
		t.Errorf("non-sensitive values should be kept: %v", redacted)
	}
	if redacted.Get("refresh_token") != redactedValue {
		t.Errorf("expected refresh_token to be redacted, got %q", redacted.Get("refresh_token"))
	}
	if data.Get("refresh_token") != secret {
		t.Error("original form data must not be modified")
	}
}

func TestRedactJSONBody(t *testing.T) {
	body := []byte(`{"access_token":"` + secret + `","refresh_token":"` + secret + `","device_code":"` + secret + `","user_code":"ABCD-EFGH","token_type":"Bearer","expires_in":3600}`)

	out := redactJSONBody(body)

	if strings.Contains(out, secret) {
		t.Errorf("redacted body still contains secret: %s", out)
	}
	for _, expected := range []string{`"user_code":"ABCD-EFGH"`, `"token_type":"Bearer"`, `"expires_in":3600`, `"access_token":"[REDACTED]"`} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected %s in redacted body: %s", expected, out)
		}
	}
}

func TestRedactJSONBodyNotJSON(t *testing.T) {
	out := redactJSONBody([]byte("access_token=" + secret))
	if strings.Contains(out, secret) {
		t.Errorf("non-JSON body must not be shown: %s", out)
	}
}

func TestTokenExchangeResponseString(t *testing.T) {
	refresh := secret
	response := TokenExchangeResponse{AccessToken: secret, RefreshToken: &refresh, TokenType: "Bearer", ExpiresIn: 60}

	for _, out := range []string{fmt.Sprint(response), fmt.Sprint(&response), fmt.Sprintf("%v", response)} {
		if strings.Contains(out, secret) {
			t.Errorf("logged TokenExchangeResponse contains secret: %s", out)
		}
		if !strings.Contains(out, "TokenType:Bearer") {
			t.Errorf("expected non-sensitive fields in output: %s", out)
		}
	}

	var nilResponse *TokenExchangeResponse
	if out := fmt.Sprint(nilResponse); out != "<nil>" {
		t.Errorf("expected <nil> for nil pointer, got %s", out)
	}
}

func TestRefreshTokenFileAndAuthorizeDeviceResponseString(t *testing.T) {
	outputs := []string{
		fmt.Sprint(RefreshTokenFile{RefreshToken: secret}),
		fmt.Sprint(AuthorizeDeviceResponse{DeviceCode: secret, UserCode: "ABCD-EFGH"}),
	}
	for _, out := range outputs {
		if strings.Contains(out, secret) {
			t.Errorf("logged struct contains secret: %s", out)
		}
	}
}
