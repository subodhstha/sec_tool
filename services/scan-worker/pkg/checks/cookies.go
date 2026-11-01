package checks

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/scan-worker/pkg/sanitizer"
)

// CookieAuditor inspects Set-Cookie headers for security attributes
type CookieAuditor struct{}

func NewCookieAuditor() *CookieAuditor {
	return &CookieAuditor{}
}

// AuditCookies evaluates all Set-Cookie headers in an HTTP response
func (a *CookieAuditor) AuditCookies(
	scanID string,
	targetURL string,
	req *http.Request,
	resp *http.Response,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)
	rawCookies := resp.Header.Values("Set-Cookie")
	if len(rawCookies) == 0 {
		return findings
	}

	for _, raw := range rawCookies {
		parts := strings.Split(raw, ";")
		if len(parts) == 0 {
			continue
		}

		nameVal := strings.TrimSpace(parts[0])
		eqIdx := strings.Index(nameVal, "=")
		cookieName := nameVal
		if eqIdx != -1 {
			cookieName = nameVal[:eqIdx]
		}

		lowerRaw := strings.ToLower(raw)
		hasSecure := strings.Contains(lowerRaw, "secure")
		hasHttpOnly := strings.Contains(lowerRaw, "httponly")
		hasSameSite := strings.Contains(lowerRaw, "samesite")

		// 1. Missing Secure Flag on HTTPS
		if !hasSecure && strings.HasPrefix(strings.ToLower(targetURL), "https://") {
			dedupHash := models.ComputeDedupHash(cookieName, "COOKIE_SECURE_FLAG", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             fmt.Sprintf("Insecure Cookie Transmission: '%s' Missing Secure Attribute", cookieName),
				Description:       fmt.Sprintf("The cookie '%s' is set without the 'Secure' flag on an HTTPS connection. It can be intercepted in cleartext if forced over HTTP.", cookieName),
				Remediation:       "Add the 'Secure' attribute to all Set-Cookie directives sent over HTTPS (e.g. Set-Cookie: id=xyz; Secure; HttpOnly; SameSite=Lax).",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityMedium,
				CVSSScore:         5.3,
				CWE:               "CWE-614",
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				ISO27001Control:  "A.8.20 Network security, A.8.24 Use of cryptography",
				NISTControl:      "SP 800-53 SC-8 Transmission Confidentiality, SC-13 Cryptography",
				NSACISAGuidance:  "CISA-MISCONFIG-04 Insecure Transmission Channels",
				TargetURL:         targetURL,
				AffectedParameter: cookieName,
				InjectionContext:  "SET_COOKIE_HEADER",
				DedupHash:         dedupHash,
				DiscoveredAt:      time.Now(),
				Proof: &models.HTTPProof{
					RequestURL:      targetURL,
					RequestMethod:   req.Method,
					RequestHeaders:  sanitizer.MaskHeaders(req.Header),
					StatusCode:      resp.StatusCode,
					ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
				},
			})
		}

		// 2. Missing HttpOnly Attribute
		if !hasHttpOnly {
			dedupHash := models.ComputeDedupHash(cookieName, "COOKIE_HTTPONLY_FLAG", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             fmt.Sprintf("Session Cookie Inaccessible Protection Missing: '%s' Missing HttpOnly", cookieName),
				Description:       fmt.Sprintf("The cookie '%s' does not have the 'HttpOnly' flag set, allowing client-side scripts to access it, exacerbating Cross-Site Scripting (XSS) impacts.", cookieName),
				Remediation:       "Configure all session and authorization cookies with the 'HttpOnly' flag.",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityMedium,
				CVSSScore:         4.3,
				CWE:               "CWE-1004",
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				ISO27001Control:  "A.8.26 Application security requirements, A.8.28 Secure coding",
				NISTControl:      "SP 800-53 SC-28 Protection of Information, SI-10 Input Validation",
				NSACISAGuidance:  "NSA Web Security Guide - Section 3.2 Session Protection",
				TargetURL:         targetURL,
				AffectedParameter: cookieName,
				InjectionContext:  "SET_COOKIE_HEADER",
				DedupHash:         dedupHash,
				DiscoveredAt:      time.Now(),
				Proof: &models.HTTPProof{
					RequestURL:      targetURL,
					RequestMethod:   req.Method,
					RequestHeaders:  sanitizer.MaskHeaders(req.Header),
					StatusCode:      resp.StatusCode,
					ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
				},
			})
		}

		// 3. Missing or Insecure SameSite Attribute
		if !hasSameSite || strings.Contains(lowerRaw, "samesite=none") {
			dedupHash := models.ComputeDedupHash(cookieName, "COOKIE_SAMESITE_FLAG", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             fmt.Sprintf("Missing or Permissive SameSite Attribute on Cookie '%s'", cookieName),
				Description:       fmt.Sprintf("The cookie '%s' lacks a strict SameSite attribute (SameSite=Lax or SameSite=Strict), increasing susceptibility to Cross-Site Request Forgery (CSRF).", cookieName),
				Remediation:       "Set SameSite=Lax or SameSite=Strict on all stateful session cookies.",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityLow,
				CVSSScore:         3.7,
				CWE:               "CWE-1275",
				OWASPCategory:     "A01:2021-Broken Access Control",
				ISO27001Control:  "A.5.15 Access control, A.8.28 Secure coding",
				NISTControl:      "SP 800-53 AC-3 Access Enforcement, SC-23 Session Authenticity",
				NSACISAGuidance:  "CISA Web App Defense - CSRF Protection Directive",
				TargetURL:         targetURL,
				AffectedParameter: cookieName,
				InjectionContext:  "SET_COOKIE_HEADER",
				DedupHash:         dedupHash,
				DiscoveredAt:      time.Now(),
				Proof: &models.HTTPProof{
					RequestURL:      targetURL,
					RequestMethod:   req.Method,
					RequestHeaders:  sanitizer.MaskHeaders(req.Header),
					StatusCode:      resp.StatusCode,
					ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
				},
			})
		}
	}

	return findings
}
