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

// ──────────────────────────────────────────────────────────────────────────────
// Advanced Security Header & CSP Deep Auditor
// Covers: Permissions-Policy, Cache-Control, Cross-Origin headers, CSP quality
// CWE-693, CWE-525, CWE-16, CWE-942
// ──────────────────────────────────────────────────────────────────────────────

// AdvancedHeaderAuditor extends the base HeaderAuditor with deep security checks
type AdvancedHeaderAuditor struct{}

func NewAdvancedHeaderAuditor() *AdvancedHeaderAuditor {
	return &AdvancedHeaderAuditor{}
}

// AuditAdvancedHeaders performs extended header analysis beyond the base HeaderAuditor
func (a *AdvancedHeaderAuditor) AuditAdvancedHeaders(
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

	// 1. Missing Permissions-Policy (formerly Feature-Policy)
	if _, exists := lowerHeaders["permissions-policy"]; !exists {
		if _, featureExists := lowerHeaders["feature-policy"]; !featureExists {
			dedupHash := models.ComputeDedupHash("Permissions-Policy", "RESPONSE_HEADER", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Missing Permissions-Policy Header",
				Description:       "The application does not set a Permissions-Policy header, allowing embedded content and third-party scripts to access powerful browser features (camera, microphone, geolocation, payment, etc.).",
				Remediation:       "Set a restrictive Permissions-Policy header, e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityLow,
				CVSSScore:         3.1,
				CWE:               "CWE-16",
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				ISO27001Control:   "A.8.9 Configuration management",
				NISTControl:       "SP 800-53 CM-6 Configuration Settings",
				TargetURL:         targetURL,
				AffectedParameter: "Permissions-Policy",
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

	// 2. Missing or Insecure Cache-Control on Sensitive Endpoints
	cacheControl := strings.ToLower(lowerHeaders["cache-control"])
	pragma := strings.ToLower(lowerHeaders["pragma"])
	isHTTPS := strings.HasPrefix(strings.ToLower(targetURL), "https://")

	// Check if the response contains potentially sensitive content
	contentType := strings.ToLower(lowerHeaders["content-type"])
	isSensitiveContent := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json")

	if isHTTPS && isSensitiveContent {
		hasNoStore := strings.Contains(cacheControl, "no-store")
		hasNoCache := strings.Contains(cacheControl, "no-cache")
		hasNoPragma := strings.Contains(pragma, "no-cache")

		if !hasNoStore && !hasNoCache && !hasNoPragma {
			dedupHash := models.ComputeDedupHash("Cache-Control", "RESPONSE_HEADER", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Missing Cache-Control Anti-Caching Directives",
				Description:       "The response does not include Cache-Control: no-store or no-cache directives. Sensitive data may be cached by browsers, proxies, or CDNs and accessible to unauthorized users on shared systems.",
				Remediation:       "Add 'Cache-Control: no-store, no-cache, must-revalidate, private' and 'Pragma: no-cache' to responses containing sensitive data.",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityLow,
				CVSSScore:         3.7,
				CWE:               "CWE-525",
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				ISO27001Control:   "A.8.10 Information deletion, A.8.11 Data masking",
				NISTControl:       "SP 800-53 SC-28 Protection of Information at Rest",
				TargetURL:         targetURL,
				AffectedParameter: "Cache-Control",
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

	// 3. Missing Cross-Origin Isolation Headers (COOP / COEP / CORP)
	if _, exists := lowerHeaders["cross-origin-opener-policy"]; !exists {
		dedupHash := models.ComputeDedupHash("COOP", "RESPONSE_HEADER", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Missing Cross-Origin-Opener-Policy (COOP) Header",
			Description:       "The application does not set a Cross-Origin-Opener-Policy header, leaving it vulnerable to cross-origin window reference attacks (Spectre-class side-channel attacks, cross-origin window manipulation).",
			Remediation:       "Set 'Cross-Origin-Opener-Policy: same-origin' to isolate the browsing context from cross-origin documents.",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityLow,
			CVSSScore:         3.1,
			CWE:               "CWE-16",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "Cross-Origin-Opener-Policy",
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

	// 4. CSP Deep Analysis — check for dangerous directives
	csp := lowerHeaders["content-security-policy"]
	if csp != "" {
		cspFindings := a.auditCSPQuality(scanID, targetURL, req, resp, csp)
		findings = append(findings, cspFindings...)
	}

	// 5. X-XSS-Protection set to unsafe value (0 disables it)
	xssProtection := lowerHeaders["x-xss-protection"]
	if xssProtection == "0" {
		dedupHash := models.ComputeDedupHash("X-XSS-Protection-Disabled", "RESPONSE_HEADER", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "X-XSS-Protection Explicitly Disabled",
			Description:       "The X-XSS-Protection header is set to '0', explicitly disabling the browser's built-in XSS filter. While modern browsers rely on CSP, disabling this header without a robust CSP increases XSS risk in legacy browsers.",
			Remediation:       "Set 'X-XSS-Protection: 1; mode=block' or remove the header entirely and rely on a strong Content-Security-Policy.",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityLow,
			CVSSScore:         3.1,
			CWE:               "CWE-16",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "X-XSS-Protection",
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

// auditCSPQuality performs in-depth analysis of Content-Security-Policy directives
func (a *AdvancedHeaderAuditor) auditCSPQuality(
	scanID string,
	targetURL string,
	req *http.Request,
	resp *http.Response,
	csp string,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)
	lowerCSP := strings.ToLower(csp)

	dangerousDirectives := []struct {
		Pattern     string
		Title       string
		Description string
		Severity    models.VulnerabilitySeverity
		CVSS        float64
		CWE         string
	}{
		{
			Pattern:     "'unsafe-inline'",
			Title:       "CSP Allows Unsafe Inline Scripts",
			Description: "The Content-Security-Policy includes 'unsafe-inline', which defeats XSS protection by allowing arbitrary inline JavaScript execution.",
			Severity:    models.SeverityMedium,
			CVSS:        5.3,
			CWE:         "CWE-693",
		},
		{
			Pattern:     "'unsafe-eval'",
			Title:       "CSP Allows Unsafe Eval",
			Description: "The Content-Security-Policy includes 'unsafe-eval', allowing dynamic code execution via eval(), Function(), setTimeout(string), etc. This significantly weakens XSS protection.",
			Severity:    models.SeverityMedium,
			CVSS:        5.3,
			CWE:         "CWE-693",
		},
		{
			Pattern:     "data:",
			Title:       "CSP Allows data: URI Scheme",
			Description: "The Content-Security-Policy permits the 'data:' URI scheme in script-src or default-src, which can be exploited for XSS via data:text/html payloads.",
			Severity:    models.SeverityMedium,
			CVSS:        5.3,
			CWE:         "CWE-693",
		},
		{
			Pattern:     "https: ",
			Title:       "CSP Uses Wildcard HTTPS Scheme",
			Description: "The CSP uses a blanket 'https:' source, allowing scripts from any HTTPS domain. This provides minimal protection against script injection from attacker-controlled HTTPS origins.",
			Severity:    models.SeverityMedium,
			CVSS:        5.3,
			CWE:         "CWE-693",
		},
	}

	for _, dd := range dangerousDirectives {
		if strings.Contains(lowerCSP, dd.Pattern) {
			dedupHash := models.ComputeDedupHash(dd.Pattern, "CSP_DIRECTIVE", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             dd.Title,
				Description:       dd.Description + fmt.Sprintf("\n\nFull CSP: %s", csp),
				Remediation:       "Remove '" + dd.Pattern + "' from the CSP. Use nonce-based or hash-based script allowlisting instead. Refactor inline scripts to external files.",
				Category:          models.CategoryInformationLeak,
				Severity:          dd.Severity,
				CVSSScore:         dd.CVSS,
				CWE:               dd.CWE,
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				ISO27001Control:   "A.8.28 Secure coding, A.8.9 Configuration management",
				NISTControl:       "SP 800-53 SI-10 Information Input Validation",
				TargetURL:         targetURL,
				AffectedParameter: "Content-Security-Policy",
				InjectionContext:  "CSP_DIRECTIVE",
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

	// Check for wildcard * in script-src or default-src
	if strings.Contains(lowerCSP, "script-src *") || strings.Contains(lowerCSP, "default-src *") {
		dedupHash := models.ComputeDedupHash("CSP-Wildcard", "CSP_DIRECTIVE", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "CSP Uses Wildcard (*) Source in Script or Default Directive",
			Description:       "The Content-Security-Policy uses '*' in script-src or default-src, effectively allowing script loading from any domain and nullifying XSS protection.\n\nFull CSP: " + csp,
			Remediation:       "Replace '*' with explicit, trusted domain allowlists in script-src and default-src directives.",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityHigh,
			CVSSScore:         7.5,
			CWE:               "CWE-693",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "Content-Security-Policy",
			InjectionContext:  "CSP_DIRECTIVE",
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

	// Check if report-only mode (not enforced)
	if _, exists := resp.Header["Content-Security-Policy-Report-Only"]; exists {
		if _, enforced := resp.Header["Content-Security-Policy"]; !enforced {
			dedupHash := models.ComputeDedupHash("CSP-Report-Only", "CSP_DIRECTIVE", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Content-Security-Policy in Report-Only Mode (Not Enforced)",
				Description:       "The application uses Content-Security-Policy-Report-Only without an enforcing CSP header. Violations are only reported, not blocked, providing zero protection against XSS.",
				Remediation:       "Deploy an enforcing Content-Security-Policy header alongside or instead of Report-Only mode.",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityMedium,
				CVSSScore:         5.0,
				CWE:               "CWE-693",
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				TargetURL:         targetURL,
				AffectedParameter: "Content-Security-Policy-Report-Only",
				InjectionContext:  "CSP_DIRECTIVE",
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

// AuditHTTPMethods tests for dangerous HTTP methods enabled on the target
func (a *AdvancedHeaderAuditor) AuditHTTPMethods(
	ctx context.Context,
	scanID string,
	targetURL string,
	client *http.Client,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)

	// Send OPTIONS to discover allowed methods
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
	if err != nil {
		return findings
	}

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")
	if allow == "" {
		// Try Access-Control-Allow-Methods from CORS
		allow = resp.Header.Get("Access-Control-Allow-Methods")
	}

	dangerousMethods := []string{"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
	allowUpper := strings.ToUpper(allow)

	for _, method := range dangerousMethods {
		if strings.Contains(allowUpper, method) {
			// Confirm with an actual request for TRACE (Cross-Site Tracing)
			if method == "TRACE" {
				traceReq, err := http.NewRequestWithContext(ctx, "TRACE", targetURL, nil)
				if err != nil {
					continue
				}
				traceResp, err := client.Do(traceReq)
				if err != nil {
					continue
				}
				traceResp.Body.Close()

				if traceResp.StatusCode == http.StatusOK {
					dedupHash := models.ComputeDedupHash("TRACE", "HTTP_METHOD", models.CategoryInformationLeak)
					findings = append(findings, models.VulnerabilityFinding{
						ID:                uuid.New().String(),
						ScanID:            scanID,
						Title:             "HTTP TRACE Method Enabled (Cross-Site Tracing)",
						Description:       "The TRACE HTTP method is enabled on the server. This can be exploited for Cross-Site Tracing (XST) attacks to steal session cookies and authentication tokens, even when HttpOnly is set.",
						Remediation:       "Disable the TRACE HTTP method on all web servers and application servers. In Apache: TraceEnable Off. In Nginx: deny TRACE in server block.",
						Category:          models.CategoryInformationLeak,
						Severity:          models.SeverityMedium,
						CVSSScore:         5.3,
						CWE:               "CWE-693",
						OWASPCategory:     "A05:2021-Security Misconfiguration",
						ISO27001Control:   "A.8.9 Configuration management",
						NISTControl:       "SP 800-53 CM-7 Least Functionality",
						TargetURL:         targetURL,
						AffectedParameter: "TRACE",
						InjectionContext:  "HTTP_METHOD",
						DedupHash:         dedupHash,
						DiscoveredAt:      time.Now(),
						Proof: &models.HTTPProof{
							RequestURL:      targetURL,
							RequestMethod:   "TRACE",
							RequestHeaders:  sanitizer.MaskHeaders(traceReq.Header),
							StatusCode:      traceResp.StatusCode,
							ResponseHeaders: sanitizer.MaskHeaders(traceResp.Header),
						},
					})
				}
			} else {
				dedupHash := models.ComputeDedupHash(method, "HTTP_METHOD", models.CategoryInformationLeak)
				findings = append(findings, models.VulnerabilityFinding{
					ID:                uuid.New().String(),
					ScanID:            scanID,
					Title:             fmt.Sprintf("Potentially Dangerous HTTP Method Enabled: %s", method),
					Description:       fmt.Sprintf("The HTTP %s method is advertised as allowed on this endpoint. If unintentional, this could allow unauthorized data modification or deletion.", method),
					Remediation:       fmt.Sprintf("Disable the %s HTTP method if it is not required by the application. Configure the web server to reject unused methods.", method),
					Category:          models.CategoryInformationLeak,
					Severity:          models.SeverityLow,
					CVSSScore:         3.7,
					CWE:               "CWE-16",
					OWASPCategory:     "A05:2021-Security Misconfiguration",
					TargetURL:         targetURL,
					AffectedParameter: method,
					InjectionContext:  "HTTP_METHOD",
					DedupHash:         dedupHash,
					DiscoveredAt:      time.Now(),
					Proof: &models.HTTPProof{
						RequestURL:      targetURL,
						RequestMethod:   http.MethodOptions,
						RequestHeaders:  sanitizer.MaskHeaders(req.Header),
						StatusCode:      resp.StatusCode,
						ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
					},
				})
			}
		}
	}

	return findings
}
