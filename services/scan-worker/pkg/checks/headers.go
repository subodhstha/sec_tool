package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/scan-worker/pkg/sanitizer"
)

// HeaderAuditor evaluates compliance against the OWASP Security Headers standard
type HeaderAuditor struct{}

func NewHeaderAuditor() *HeaderAuditor {
	return &HeaderAuditor{}
}

// AuditHeaders tests response headers for essential security directives
func (a *HeaderAuditor) AuditHeaders(
	scanID string,
	targetURL string,
	req *http.Request,
	resp *http.Response,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)
	lowerHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			lowerHeaders[strings.ToLower(k)] = v[0]
		}
	}

	// 1. Missing HSTS (Strict-Transport-Security) over HTTPS
	if strings.HasPrefix(strings.ToLower(targetURL), "https://") {
		if hsts, exists := lowerHeaders["strict-transport-security"]; !exists || hsts == "" {
			dedupHash := models.ComputeDedupHash("Strict-Transport-Security", "RESPONSE_HEADER", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Missing HTTP Strict-Transport-Security (HSTS) Header",
				Description:       "The server does not enforce HTTPS communication using HSTS, allowing downgrade man-in-the-middle attacks.",
				Remediation:       "Configure Strict-Transport-Security with a minimum max-age of 31536000 (1 year) and includeSubDomains.",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityMedium,
				CVSSScore:         5.9,
				CWE:               "CWE-319",
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				TargetURL:         targetURL,
				AffectedParameter: "Strict-Transport-Security",
				InjectionContext:  "RESPONSE_HEADER",
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

	// 2. Missing X-Content-Type-Options: nosniff
	if xcto, exists := lowerHeaders["x-content-type-options"]; !exists || strings.ToLower(xcto) != "nosniff" {
		dedupHash := models.ComputeDedupHash("X-Content-Type-Options", "RESPONSE_HEADER", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Missing X-Content-Type-Options Header",
			Description:       "The response lacks 'X-Content-Type-Options: nosniff', which permits MIME-confusion attacks and executable sniffing.",
			Remediation:       "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityLow,
			CVSSScore:         3.4,
			CWE:               "CWE-16",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "X-Content-Type-Options",
			InjectionContext:  "RESPONSE_HEADER",
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

	// 3. Missing X-Frame-Options or frame-ancestors in CSP (Clickjacking Defense)
	csp := lowerHeaders["content-security-policy"]
	xfo := lowerHeaders["x-frame-options"]
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")

	if xfo == "" && !hasFrameAncestors {
		dedupHash := models.ComputeDedupHash("X-Frame-Options", "RESPONSE_HEADER", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Missing Anti-Clickjacking Header (X-Frame-Options / CSP frame-ancestors)",
			Description:       "The application does not declare framing protections, exposing users to UI redressing / clickjacking attacks.",
			Remediation:       "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and specify 'frame-ancestors' directive in Content-Security-Policy.",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityMedium,
			CVSSScore:         4.7,
			CWE:               "CWE-1021",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "X-Frame-Options",
			InjectionContext:  "RESPONSE_HEADER",
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

	// 4. Missing Content-Security-Policy (CSP)
	if csp == "" {
		dedupHash := models.ComputeDedupHash("Content-Security-Policy", "RESPONSE_HEADER", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Missing Content-Security-Policy (CSP)",
			Description:       "No Content-Security-Policy header was detected, failing to restrict unauthorized scripts, styles, and data injections.",
			Remediation:       "Implement a Content-Security-Policy (e.g. default-src 'self').",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityMedium,
			CVSSScore:         5.0,
			CWE:               "CWE-693",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "Content-Security-Policy",
			InjectionContext:  "RESPONSE_HEADER",
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

	// 5. Missing Referrer-Policy
	if refPolicy, exists := lowerHeaders["referrer-policy"]; !exists || refPolicy == "" {
		dedupHash := models.ComputeDedupHash("Referrer-Policy", "RESPONSE_HEADER", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Missing Referrer-Policy Header",
			Description:       "The application does not set a Referrer-Policy header, which may leak sensitive URL parameters or internal paths to external sites.",
			Remediation:       "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityLow,
			CVSSScore:         3.1,
			CWE:               "CWE-116",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "Referrer-Policy",
			InjectionContext:  "RESPONSE_HEADER",
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

	return findings
}

// AuditCORS probes the endpoint for permissive Cross-Origin Resource Sharing configurations
func (a *HeaderAuditor) AuditCORS(
	ctx context.Context,
	scanID string,
	targetURL string,
	client *http.Client,
) *models.VulnerabilityFinding {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
	if err != nil {
		return nil
	}

	testOrigin := "https://vyomite-cors-test.internal"
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials")) == "true"

	// Critical Misconfiguration: Reflected arbitrary origin + Allow-Credentials: true
	if (allowOrigin == testOrigin || allowOrigin == "*") && allowCreds {
		dedupHash := models.ComputeDedupHash("Access-Control-Allow-Origin", "CORS_PREFLIGHT", models.CategoryInformationLeak)
		return &models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Insecure CORS Configuration: Arbitrary Origin with Credentials Allowed",
			Description:       fmt.Sprintf("The server reflected the untrusted origin '%s' with 'Access-Control-Allow-Credentials: true', permitting any malicious site to read authenticated session responses via cross-origin requests.", allowOrigin),
			Remediation:       "Do not reflect untrusted Origin headers. Maintain an explicit whitelist of authorized domains and never pair '*' with Allow-Credentials: true.",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityHigh,
			CVSSScore:         7.5,
			CWE:               "CWE-942",
			OWASPCategory:     "A01:2021-Broken Access Control",
			TargetURL:         targetURL,
			AffectedParameter: "Origin",
			InjectionContext:  "CORS_HEADER",
			DedupHash:         dedupHash,
			DiscoveredAt:      time.Now(),
			Proof: &models.HTTPProof{
				RequestURL:      targetURL,
				RequestMethod:   http.MethodOptions,
				RequestHeaders:  sanitizer.MaskHeaders(req.Header),
				StatusCode:      resp.StatusCode,
				ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
			},
		}
	}

	return nil
}
