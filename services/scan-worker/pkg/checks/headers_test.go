package checks

import (
	"net/http"
	"testing"
)

func TestHeaderAuditor(t *testing.T) {
	auditor := NewHeaderAuditor()

	req, _ := http.NewRequest(http.MethodGet, "https://staging.vyomite.internal/dashboard", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}

	// Missing all security headers on HTTPS
	findings := auditor.AuditHeaders("scan-1", "https://staging.vyomite.internal/dashboard", req, resp)

	// Should flag: HSTS, X-Content-Type-Options, Anti-Clickjacking, CSP, Referrer-Policy
	if len(findings) < 5 {
		t.Fatalf("Expected at least 5 header findings, got %d", len(findings))
	}

	// Now configure hardened headers
	respHardened := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	respHardened.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	respHardened.Header.Set("X-Content-Type-Options", "nosniff")
	respHardened.Header.Set("X-Frame-Options", "DENY")
	respHardened.Header.Set("Content-Security-Policy", "default-src 'self'")
	respHardened.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")

	cleanFindings := auditor.AuditHeaders("scan-1", "https://staging.vyomite.internal/dashboard", req, respHardened)
	if len(cleanFindings) != 0 {
		t.Fatalf("Expected 0 findings for hardened headers, got %d", len(cleanFindings))
	}
}
