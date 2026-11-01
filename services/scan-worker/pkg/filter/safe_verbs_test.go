package filter

import (
	"testing"
)

func TestSafeVerbEnforcement(t *testing.T) {
	enforcer := NewSafeVerbEnforcer(true, []string{`(?i)/internal/admin`})

	tests := []struct {
		method   string
		rawURL   string
		expected bool
		reason   string
	}{
		{"GET", "https://app.local/api/items", true, "READ_ONLY_METHOD"},
		{"HEAD", "https://app.local/healthz", true, "READ_ONLY_METHOD"},
		{"POST", "https://app.local/api/items", true, "ALLOWED"},
		{"DELETE", "https://app.local/api/items/1", false, "DESTRUCTIVE_VERB_DELETE"},
		{"POST", "https://app.local/api/items/delete", false, "DESTRUCTIVE_SEMANTIC_MATCH"},
		{"PUT", "https://app.local/users/purge", false, "DESTRUCTIVE_SEMANTIC_MATCH"},
		{"PATCH", "https://app.local/database/drop", false, "DESTRUCTIVE_SEMANTIC_MATCH"},
		{"GET", "https://app.local/internal/admin/dashboard", false, "CUSTOM_EXCLUSION_RULE"},
	}

	for _, tt := range tests {
		allowed, reason := enforcer.IsRequestAllowed(tt.method, tt.rawURL)
		if allowed != tt.expected {
			t.Errorf("[%s %s] Expected allowed=%v (reason %s), got allowed=%v (reason %s)",
				tt.method, tt.rawURL, tt.expected, tt.reason, allowed, reason)
		}
	}
}
