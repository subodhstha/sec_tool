package sanitizer

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

var (
	bearerRegex = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*`)
	basicRegex  = regexp.MustCompile(`(?i)(Basic\s+)[A-Za-z0-9+/]+=*`)
	cookieRegex = regexp.MustCompile(`(?i)((?:session|jwt|token|phpsessid|connect\.sid|auth|id_token)=)[^;\s]+`)
	jsonSensitiveRegex = regexp.MustCompile(`(?i)("(?:password|secret|token|api_key|access_token|refresh_token|private_key)"\s*:\s*)"([^"]+)"`)
)

// MaskHeaders sanitizes sensitive HTTP headers before persisting or logging (Part 3.3)
func MaskHeaders(headers http.Header) map[string][]string {
	sanitized := make(map[string][]string, len(headers))
	for k, vals := range headers {
		lowerKey := strings.ToLower(k)
		maskedVals := make([]string, len(vals))

		for i, v := range vals {
			if lowerKey == "authorization" {
				v = bearerRegex.ReplaceAllString(v, "${1}[REDACTED]")
				v = basicRegex.ReplaceAllString(v, "${1}[REDACTED]")
			} else if lowerKey == "cookie" || lowerKey == "set-cookie" {
				v = cookieRegex.ReplaceAllString(v, "${1}[REDACTED]")
			} else if strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "secret") || strings.Contains(lowerKey, "key") {
				v = "[REDACTED]"
			}
			maskedVals[i] = v
		}
		sanitized[k] = maskedVals
	}
	return sanitized
}

// MaskBody sanitizes sensitive string content or JSON bodies before database storage (Part 3.3)
func MaskBody(body string) string {
	if body == "" {
		return ""
	}

	// 1. Mask JSON sensitive keys if body looks like JSON
	if strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[") {
		var js interface{}
		if err := json.Unmarshal([]byte(body), &js); err == nil {
			body = jsonSensitiveRegex.ReplaceAllString(body, `$1"[REDACTED]"`)
			return body
		}
	}

	// 2. Generic regex mask for tokens / passwords
	body = bearerRegex.ReplaceAllString(body, "${1}[REDACTED]")
	body = cookieRegex.ReplaceAllString(body, "${1}[REDACTED]")

	return body
}
