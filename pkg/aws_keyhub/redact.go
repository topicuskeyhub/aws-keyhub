package aws_keyhub

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const redactedValue = "[REDACTED]"

// sensitiveKeys lists form fields and JSON properties whose values must never be written to (debug) output.
var sensitiveKeys = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
	"subject_token": true,
	"id_token":      true,
	"device_code":   true,
	"code":          true,
	"client_secret": true,
}

// isSensitiveKey matches case-insensitively, like encoding/json does when mapping JSON properties to struct fields.
func isSensitiveKey(key string) bool {
	return sensitiveKeys[strings.ToLower(key)]
}

// redact masks a sensitive value. An empty value stays empty so debug output still shows whether a value was present.
func redact(value string) string {
	if value == "" {
		return ""
	}
	return redactedValue
}

// redactFormData returns a copy of the form data with all sensitive values masked.
func redactFormData(data url.Values) url.Values {
	redacted := make(url.Values, len(data))
	for key, values := range data {
		copied := make([]string, len(values))
		for i, value := range values {
			if isSensitiveKey(key) {
				copied[i] = redact(value)
			} else {
				copied[i] = value
			}
		}
		redacted[key] = copied
	}
	return redacted
}

// redactJSONBody returns the JSON body as a string with all sensitive top-level properties masked.
// Bodies that cannot be parsed as a JSON object are not returned at all, since their contents are unknown.
func redactJSONBody(body []byte) string {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Sprintf("[unparsable body of %d bytes not shown]", len(body))
	}
	for key, value := range parsed {
		if !isSensitiveKey(key) {
			continue
		}
		if s, ok := value.(string); ok {
			parsed[key] = redact(s)
		} else if value != nil {
			parsed[key] = redactedValue
		}
	}
	redacted, err := json.Marshal(parsed)
	if err != nil {
		return fmt.Sprintf("[body of %d bytes not shown]", len(body))
	}
	return string(redacted)
}

// String masks the tokens so a TokenExchangeResponse can safely be logged.
func (t TokenExchangeResponse) String() string {
	refreshToken := "<nil>"
	if t.RefreshToken != nil {
		refreshToken = redact(*t.RefreshToken)
	}
	return fmt.Sprintf("{AccessToken:%s RefreshToken:%s Scope:%s TokenType:%s IssuedTokenType:%s ExpiresIn:%d}",
		redact(t.AccessToken), refreshToken, t.Scope, t.TokenType, t.IssuedTokenType, t.ExpiresIn)
}

// String masks the refresh token so a RefreshTokenFile can safely be logged.
func (r RefreshTokenFile) String() string {
	return fmt.Sprintf("{RefreshToken:%s ExpireDate:%s}", redact(r.RefreshToken), r.ExpireDate)
}

// String masks the device code so an AuthorizeDeviceResponse can safely be logged.
func (a AuthorizeDeviceResponse) String() string {
	return fmt.Sprintf("{UserCode:%s DeviceCode:%s Interval:%d VerificationUriComplete:%s VerificationUri:%s ExpiresIn:%d}",
		a.UserCode, redact(a.DeviceCode), a.Interval, a.VerificationUriComplete, a.VerificationUri, a.ExpiresIn)
}
