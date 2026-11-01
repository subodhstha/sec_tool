package filter

import (
	"net/url"
	"regexp"
	"strings"
)

// DestructiveEndpointPatterns defines regexes identifying potentially destructive actions
var defaultDestructivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:^|/)(delete|remove|destroy|purge|drop|truncate|wipe|erase|clear)(?:/|$|\.|\?)`),
	regexp.MustCompile(`(?i)(?:^|/)(cancel|abort|terminate|kill|shutdown|reset|uninstall)(?:/|$|\.|\?)`),
	regexp.MustCompile(`(?i)(?:^|/)(revoke|expire|deactivate|ban|kick)(?:/|$|\.|\?)`),
}

// SafeVerbEnforcer validates whether a given HTTP method and path are permitted under Safe Mode (FR-4.2)
type SafeVerbEnforcer struct {
	safeMode         bool
	customExcludes   []*regexp.Regexp
}

// NewSafeVerbEnforcer initializes the enforcer
func NewSafeVerbEnforcer(safeMode bool, customExcludes []string) *SafeVerbEnforcer {
	compiledExcludes := make([]*regexp.Regexp, 0, len(customExcludes))
	for _, pattern := range customExcludes {
		if re, err := regexp.Compile(pattern); err == nil {
			compiledExcludes = append(compiledExcludes, re)
		}
	}

	return &SafeVerbEnforcer{
		safeMode:       safeMode,
		customExcludes: compiledExcludes,
	}
}

// IsRequestAllowed checks if a request is safe to execute
func (e *SafeVerbEnforcer) IsRequestAllowed(method, rawURL string) (bool, string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, "MALFORMED_URL"
	}

	path := parsed.Path
	methodUpper := strings.ToUpper(method)

	// Check custom user exclusion regexes first
	for _, re := range e.customExcludes {
		if re.MatchString(rawURL) || re.MatchString(path) {
			return false, "CUSTOM_EXCLUSION_RULE"
		}
	}

	// If safe mode is not enabled, non-excluded requests are allowed
	if !e.safeMode {
		return true, "ALLOWED"
	}

	// Safe Mode Rule 1: Always allow idempotent, read-only HTTP methods
	if methodUpper == "GET" || methodUpper == "HEAD" || methodUpper == "OPTIONS" {
		return true, "READ_ONLY_METHOD"
	}

	// Safe Mode Rule 2: In Safe Mode, unconditionally block HTTP DELETE
	if methodUpper == "DELETE" {
		return false, "DESTRUCTIVE_VERB_DELETE"
	}

	// Safe Mode Rule 3: For state-changing verbs (POST, PUT, PATCH), check for destructive semantics
	if methodUpper == "POST" || methodUpper == "PUT" || methodUpper == "PATCH" {
		for _, re := range defaultDestructivePatterns {
			if re.MatchString(path) {
				return false, "DESTRUCTIVE_SEMANTIC_MATCH"
			}
		}
	}

	return true, "ALLOWED"
}
