package checks

import (
	"net/http"
	"testing"
)

func TestCookieAuditorFlags(t *testing.T) {
	auditor := NewCookieAuditor()

	req, _ := http.NewRequest(http.MethodGet, "https://staging.vyomite.internal/account", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}

	// 1. Insecure cookie: missing Secure, HttpOnly, and SameSite
	resp.Header.Add("Set-Cookie", "session_id=abc12345; Path=/")

	findings := auditor.AuditCookies("scan-1", "https://staging.vyomite.internal/account", req, resp)
	if len(findings) != 3 {
		t.Fatalf("Expected 3 findings (missing Secure, HttpOnly, and SameSite), got %d", len(findings))
	}

	// 2. Properly hardened cookie
	respSecure := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	respSecure.Header.Add("Set-Cookie", "session_id=abc12345; Path=/; Secure; HttpOnly; SameSite=Strict")

	cleanFindings := auditor.AuditCookies("scan-1", "https://staging.vyomite.internal/account", req, respSecure)
	if len(cleanFindings) != 0 {
		t.Fatalf("Expected 0 findings for hardened cookie, got %d", len(cleanFindings))
	}
}
