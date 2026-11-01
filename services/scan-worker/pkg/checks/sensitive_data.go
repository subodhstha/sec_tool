package checks

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/scan-worker/pkg/sanitizer"
)

// ──────────────────────────────────────────────────────────────────────────────
// Information Disclosure & Sensitive Data Exposure Auditor
// Covers: CWE-200, CWE-209, CWE-215, CWE-497, CWE-548, CWE-532
// ──────────────────────────────────────────────────────────────────────────────

// InformationDisclosureAuditor detects sensitive data leaks in HTTP responses
type InformationDisclosureAuditor struct{}

func NewInformationDisclosureAuditor() *InformationDisclosureAuditor {
	return &InformationDisclosureAuditor{}
}

// stackTracePattern detects common framework stack traces
var stackTracePatterns = []struct {
	Name      string
	Pattern   *regexp.Regexp
	CWE       string
	Severity  models.VulnerabilitySeverity
	CVSS      float64
	Stack     string
}{
	{
		Name:     "Java / Spring Stack Trace",
		Pattern:  regexp.MustCompile(`(?i)(java\.(lang|io|sql|util)\.\w+Exception|at\s+[\w$.]+\([\w.]+:\d+\)|org\.springframework\.|org\.apache\.)`),
		CWE:      "CWE-209",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
		Stack:    "Java",
	},
	{
		Name:     "Python Traceback",
		Pattern:  regexp.MustCompile(`(?i)(Traceback \(most recent call last\)|File "[\w/\\.]+\.py", line \d+|django\.core\.exceptions|flask\.debughelpers)`),
		CWE:      "CWE-209",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
		Stack:    "Python",
	},
	{
		Name:     "PHP Error / Warning",
		Pattern:  regexp.MustCompile(`(?i)(Fatal error:|Warning:|Parse error:|Notice:)\s*(Uncaught|Allowed memory|in\s+/[\w/]+\.php\s+on\s+line\s+\d+)`),
		CWE:      "CWE-209",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
		Stack:    "PHP",
	},
	{
		Name:     ".NET / ASP.NET Stack Trace",
		Pattern:  regexp.MustCompile(`(?i)(System\.(NullReferenceException|ArgumentException|InvalidOperationException|Data\.SqlClient)|Server Error in|Stack Trace:|at\s+[\w.]+\s+in\s+[\w:\\/.]+:\s*line\s+\d+)`),
		CWE:      "CWE-209",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
		Stack:    ".NET",
	},
	{
		Name:     "Node.js / Express Error",
		Pattern:  regexp.MustCompile(`(?i)(ReferenceError:|TypeError:|SyntaxError:|Error:\s+Cannot find module|at\s+(Object\.|Module\.|Function\.)?\w+\s+\([\w/\\.]+:\d+:\d+\))`),
		CWE:      "CWE-209",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
		Stack:    "Node.js",
	},
	{
		Name:     "Ruby / Rails Error",
		Pattern:  regexp.MustCompile(`(?i)(ActionController::RoutingError|ActiveRecord::RecordNotFound|NoMethodError|RuntimeError.*\.rb:\d+)`),
		CWE:      "CWE-209",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
		Stack:    "Ruby",
	},
	{
		Name:     "Go Panic / Runtime Error",
		Pattern:  regexp.MustCompile(`goroutine \d+ \[running\]:|panic:|runtime error:`),
		CWE:      "CWE-209",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
		Stack:    "Go",
	},
}

// sensitiveDataPatterns detects leaked credentials, tokens, and secrets in responses
var sensitiveDataPatterns = []struct {
	Name     string
	Pattern  *regexp.Regexp
	CWE      string
	Severity models.VulnerabilitySeverity
	CVSS     float64
}{
	{
		Name:     "AWS Access Key Leak",
		Pattern:  regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		CWE:      "CWE-200",
		Severity: models.SeverityCritical,
		CVSS:     9.8,
	},
	{
		Name:     "Private Key Material Leak",
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		CWE:      "CWE-200",
		Severity: models.SeverityCritical,
		CVSS:     9.8,
	},
	{
		Name:     "Generic API Key / Token Leak",
		Pattern:  regexp.MustCompile(`(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}["']?`),
		CWE:      "CWE-200",
		Severity: models.SeverityHigh,
		CVSS:     7.5,
	},
	{
		Name:     "Database Connection String Leak",
		Pattern:  regexp.MustCompile(`(?i)(mysql|postgres|mongodb|mssql|redis|amqp)://[^\s"'<>]+@[^\s"'<>]+`),
		CWE:      "CWE-200",
		Severity: models.SeverityCritical,
		CVSS:     9.8,
	},
	{
		Name:     "Email Address Exposure (Bulk)",
		Pattern:  regexp.MustCompile(`[a-zA-Z0-9._%+\-]{3,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		CWE:      "CWE-200",
		Severity: models.SeverityLow,
		CVSS:     3.1,
	},
	{
		Name:     "Internal IP Address Disclosure",
		Pattern:  regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`),
		CWE:      "CWE-200",
		Severity: models.SeverityLow,
		CVSS:     3.7,
	},
	{
		Name:     "JWT Token in Response Body",
		Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		CWE:      "CWE-200",
		Severity: models.SeverityMedium,
		CVSS:     5.3,
	},
	{
		Name:     "Password / Secret in HTML Comment",
		Pattern:  regexp.MustCompile(`(?i)<!--[^>]*(password|secret|token|api.?key|credentials)\s*[=:]\s*\S+[^>]*-->`),
		CWE:      "CWE-615",
		Severity: models.SeverityHigh,
		CVSS:     7.5,
	},
	{
		Name:     "Source Map File Reference",
		Pattern:  regexp.MustCompile(`//[#@]\s*sourceMappingURL=\S+\.map`),
		CWE:      "CWE-540",
		Severity: models.SeverityLow,
		CVSS:     3.1,
	},
	{
		Name:     "Google Cloud / GCP Service Account Key",
		Pattern:  regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		CWE:      "CWE-200",
		Severity: models.SeverityCritical,
		CVSS:     9.8,
	},
	{
		Name:     "Slack Webhook URL",
		Pattern:  regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}`),
		CWE:      "CWE-200",
		Severity: models.SeverityHigh,
		CVSS:     7.5,
	},
	{
		Name:     "GitHub Personal Access Token",
		Pattern:  regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		CWE:      "CWE-200",
		Severity: models.SeverityCritical,
		CVSS:     9.8,
	},
}

// AuditResponseBody scans the HTTP response body for information disclosure
func (a *InformationDisclosureAuditor) AuditResponseBody(
	scanID string,
	targetURL string,
	req *http.Request,
	resp *http.Response,
	body string,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)

	// Limit body scanning to prevent performance issues
	scanBody := body
	if len(scanBody) > 256*1024 {
		scanBody = scanBody[:256*1024]
	}

	// 1. Stack Trace Detection
	for _, st := range stackTracePatterns {
		if st.Pattern.MatchString(scanBody) {
			loc := st.Pattern.FindStringIndex(scanBody)
			evidence := ""
			if loc != nil {
				end := loc[1] + 100
				if end > len(scanBody) {
					end = len(scanBody)
				}
				evidence = scanBody[loc[0]:end]
			}

			dedupHash := models.ComputeDedupHash(st.Name, "RESPONSE_BODY", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Stack Trace / Debug Information Exposure: " + st.Name,
				Description:       "The server response contains a " + st.Stack + " stack trace or debug error message, revealing internal application paths, framework versions, and potentially sensitive runtime information to attackers.",
				Remediation:       "Configure custom error pages for all HTTP error status codes. Disable debug mode and verbose error reporting in production. Use structured logging that does not expose stack traces to end users.",
				Category:          models.CategoryInformationLeak,
				Severity:          st.Severity,
				CVSSScore:         st.CVSS,
				CWE:               st.CWE,
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				ISO27001Control:   "A.8.28 Secure coding, A.8.9 Configuration management",
				NISTControl:       "SP 800-53 SI-11 Error Handling",
				NSACISAGuidance:   "CISA-MISCONFIG-01 Verbose Error Messages",
				TargetURL:         targetURL,
				AffectedParameter: "response_body",
				InjectionContext:  "RESPONSE_BODY",
				DedupHash:         dedupHash,
				DiscoveredAt:      time.Now(),
				Proof: &models.HTTPProof{
					RequestURL:      targetURL,
					RequestMethod:   req.Method,
					RequestHeaders:  sanitizer.MaskHeaders(req.Header),
					StatusCode:      resp.StatusCode,
					ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
					ResponseBody:    sanitizer.MaskBody(evidence),
				},
			})
		}
	}

	// 2. Sensitive Data Pattern Detection
	for _, sd := range sensitiveDataPatterns {
		if sd.Pattern.MatchString(scanBody) {
			loc := sd.Pattern.FindStringIndex(scanBody)
			evidence := ""
			if loc != nil {
				start := loc[0] - 20
				if start < 0 {
					start = 0
				}
				end := loc[1] + 20
				if end > len(scanBody) {
					end = len(scanBody)
				}
				evidence = scanBody[start:end]
			}

			dedupHash := models.ComputeDedupHash(sd.Name, "RESPONSE_BODY", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Sensitive Data Exposure: " + sd.Name,
				Description:       "The response body contains what appears to be a " + sd.Name + ". This could expose credentials, tokens, or internal infrastructure details to unauthorized users.",
				Remediation:       "Remove all sensitive data from HTTP responses. Use environment variables for secrets, never hardcode credentials. Review application logs and error handlers for data leaks. Apply the principle of least privilege for API responses.",
				Category:          models.CategoryInformationLeak,
				Severity:          sd.Severity,
				CVSSScore:         sd.CVSS,
				CWE:               sd.CWE,
				OWASPCategory:     "A02:2021-Cryptographic Failures",
				ISO27001Control:   "A.8.11 Data masking, A.5.33 Protection of records",
				NISTControl:       "SP 800-53 SC-28 Protection of Information at Rest, AC-4 Information Flow",
				NSACISAGuidance:   "CISA-SECRET-01 Credential Exposure Prevention",
				TargetURL:         targetURL,
				AffectedParameter: "response_body",
				InjectionContext:  "RESPONSE_BODY",
				DedupHash:         dedupHash,
				DiscoveredAt:      time.Now(),
				Proof: &models.HTTPProof{
					RequestURL:      targetURL,
					RequestMethod:   req.Method,
					RequestHeaders:  sanitizer.MaskHeaders(req.Header),
					StatusCode:      resp.StatusCode,
					ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
					ResponseBody:    sanitizer.MaskBody(evidence),
				},
			})
		}
	}

	return findings
}

// AuditServerVersionHeaders checks for server version disclosure in response headers
func (a *InformationDisclosureAuditor) AuditServerVersionHeaders(
	scanID string,
	targetURL string,
	req *http.Request,
	resp *http.Response,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)

	versionPattern := regexp.MustCompile(`[\d]+\.[\d]+`)

	headersToCheck := []struct {
		Name  string
		Value string
	}{
		{"Server", resp.Header.Get("Server")},
		{"X-Powered-By", resp.Header.Get("X-Powered-By")},
		{"X-AspNet-Version", resp.Header.Get("X-AspNet-Version")},
		{"X-AspNetMvc-Version", resp.Header.Get("X-AspNetMvc-Version")},
		{"X-Generator", resp.Header.Get("X-Generator")},
		{"X-Drupal-Cache", resp.Header.Get("X-Drupal-Cache")},
		{"X-Varnish", resp.Header.Get("X-Varnish")},
	}

	for _, hdr := range headersToCheck {
		if hdr.Value != "" && versionPattern.MatchString(hdr.Value) {
			dedupHash := models.ComputeDedupHash(hdr.Name, "SERVER_VERSION_HEADER", models.CategoryInformationLeak)
			findings = append(findings, models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Server Version Disclosure via " + hdr.Name + " Header",
				Description:       "The '" + hdr.Name + ": " + hdr.Value + "' header reveals the server software version. Attackers can use this to identify known vulnerabilities for that specific version.",
				Remediation:       "Remove or suppress version information from HTTP response headers. Configure your web server to hide version strings (e.g., 'ServerTokens Prod' for Apache, 'server_tokens off' for Nginx).",
				Category:          models.CategoryInformationLeak,
				Severity:          models.SeverityLow,
				CVSSScore:         3.7,
				CWE:               "CWE-200",
				OWASPCategory:     "A05:2021-Security Misconfiguration",
				ISO27001Control:   "A.8.9 Configuration management",
				NISTControl:       "SP 800-53 SC-8 Transmission Confidentiality",
				TargetURL:         targetURL,
				AffectedParameter: hdr.Name,
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

	// Check for X-Powered-By header without version (still a disclosure)
	xpb := resp.Header.Get("X-Powered-By")
	if xpb != "" && !versionPattern.MatchString(xpb) {
		dedupHash := models.ComputeDedupHash("X-Powered-By-NoVersion", "SERVER_TECH_HEADER", models.CategoryInformationLeak)
		findings = append(findings, models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Technology Stack Disclosure via X-Powered-By Header",
			Description:       "The 'X-Powered-By: " + xpb + "' header reveals the server-side technology stack, aiding attacker reconnaissance.",
			Remediation:       "Remove the X-Powered-By header from all responses. Most frameworks allow disabling this header (e.g., app.disable('x-powered-by') in Express).",
			Category:          models.CategoryInformationLeak,
			Severity:          models.SeverityInfo,
			CVSSScore:         0.0,
			CWE:               "CWE-200",
			OWASPCategory:     "A05:2021-Security Misconfiguration",
			TargetURL:         targetURL,
			AffectedParameter: "X-Powered-By",
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

// AuditDebugEndpoints probes common debug/admin endpoints that should not be publicly accessible
func (a *InformationDisclosureAuditor) AuditDebugEndpoints(
	ctx context.Context,
	scanID string,
	targetBaseURL string,
	client *http.Client,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)

	debugPaths := []struct {
		Path        string
		Signature   string
		Title       string
		Severity    models.VulnerabilitySeverity
		CVSS        float64
		CWE         string
		Description string
		Remediation string
	}{
		{"/debug/pprof/", "Types of profiles", "Go pprof Debug Endpoint Exposed", models.SeverityHigh, 7.5, "CWE-215", "Go pprof profiling endpoint is publicly accessible, leaking CPU/memory profiling data, goroutine dumps, and heap snapshots.", "Remove pprof handlers from production builds or protect them behind authentication."},
		{"/actuator", "\"_links\"", "Spring Boot Actuator Exposed", models.SeverityCritical, 9.1, "CWE-215", "Spring Boot Actuator endpoints are publicly accessible, potentially exposing env variables, beans, health, and heap dumps.", "Secure all actuator endpoints behind authentication. Disable unnecessary endpoints in production."},
		{"/actuator/env", "\"property\"", "Spring Boot Actuator /env Exposed", models.SeverityCritical, 9.8, "CWE-215", "Spring Boot /actuator/env endpoint exposes environment variables including potential secrets.", "Disable the /env endpoint or restrict access with Spring Security."},
		{"/actuator/heapdump", "", "Spring Boot Heap Dump Accessible", models.SeverityCritical, 9.8, "CWE-215", "Spring Boot /actuator/heapdump is accessible and can expose in-memory credentials and secrets.", "Disable heapdump endpoint in production."},
		{"/__debug__/", "", "Django Debug Toolbar Exposed", models.SeverityHigh, 7.5, "CWE-215", "Django Debug Toolbar is accessible in production, exposing SQL queries, request data, and settings.", "Set DEBUG=False and remove debug middleware in production."},
		{"/elmah.axd", "Error Log", ".NET ELMAH Error Log Exposed", models.SeverityHigh, 7.5, "CWE-215", "ASP.NET ELMAH error log handler is publicly accessible, exposing application errors and stack traces.", "Restrict elmah.axd access to authenticated administrators only."},
		{"/server-status", "Apache Server Status", "Apache Server Status Page Exposed", models.SeverityMedium, 5.3, "CWE-200", "Apache mod_status is publicly accessible, revealing active connections, request details, and server load.", "Restrict /server-status to trusted IPs or disable mod_status in production."},
		{"/server-info", "Apache Server Information", "Apache Server Info Page Exposed", models.SeverityMedium, 5.3, "CWE-200", "Apache mod_info is publicly accessible, revealing server configuration details.", "Restrict /server-info to trusted IPs or disable mod_info."},
		{"/wp-json/wp/v2/users", "\"slug\"", "WordPress User Enumeration via REST API", models.SeverityMedium, 5.3, "CWE-200", "WordPress REST API exposes user enumeration, revealing usernames that can be used for brute-force attacks.", "Disable the users REST API endpoint or require authentication."},
		{"/graphql", "\"data\"", "GraphQL Endpoint Publicly Accessible", models.SeverityMedium, 5.3, "CWE-200", "A GraphQL endpoint is publicly accessible without authentication, potentially allowing schema introspection and data exfiltration.", "Require authentication for GraphQL endpoints. Disable introspection in production."},
		{"/.well-known/openid-configuration", "issuer", "OpenID Configuration Disclosure", models.SeverityInfo, 0.0, "CWE-200", "OpenID Connect discovery document is publicly accessible (expected behavior, but may reveal internal endpoints).", "Review the OpenID configuration to ensure no sensitive internal endpoints are exposed."},
		{"/swagger-ui.html", "swagger", "Swagger UI Exposed in Production", models.SeverityMedium, 5.3, "CWE-200", "Swagger UI documentation is publicly accessible, revealing all API endpoints, parameters, and data models.", "Restrict Swagger UI to development environments or protect behind authentication."},
		{"/api-docs", "\"openapi\"", "OpenAPI Specification Exposed", models.SeverityMedium, 5.3, "CWE-200", "OpenAPI specification document is publicly accessible, revealing complete API structure.", "Restrict API documentation endpoints to authorized users."},
		{"/console", "Web Console", "Debug Console Exposed (e.g. Werkzeug/Rails)", models.SeverityCritical, 9.8, "CWE-215", "An interactive debug console is publicly accessible, allowing arbitrary code execution on the server.", "Remove debug consoles from production deployments entirely."},
		{"/trace", "\"timestamp\"", "Spring Boot /trace Endpoint Exposed", models.SeverityHigh, 7.5, "CWE-200", "Spring Boot /trace endpoint is accessible, exposing recent HTTP request/response details including headers and session tokens.", "Disable or authenticate the /trace endpoint in production."},
		{"/metrics", "\"", "Metrics Endpoint Exposed (Prometheus/Spring)", models.SeverityMedium, 5.3, "CWE-200", "Application metrics endpoint is publicly accessible, revealing performance data, error rates, and internal resource names.", "Protect metrics endpoints behind authentication or network-level access controls."},
		{"/health", "\"status\"", "Health Check Endpoint Exposed", models.SeverityInfo, 0.0, "CWE-200", "Health check endpoint reveals application status and potentially connected service health.", "Ensure health endpoints do not expose detailed internal service information."},
		{"/.DS_Store", "\x00\x00\x00\x01Bud1", "macOS .DS_Store File Exposed", models.SeverityMedium, 5.3, "CWE-538", "A macOS .DS_Store file is accessible, revealing directory structure and filenames.", "Block .DS_Store files in web server configuration and remove them from deployments."},
		{"/crossdomain.xml", "cross-domain-policy", "Flash Cross-Domain Policy File", models.SeverityMedium, 5.3, "CWE-942", "A Flash cross-domain policy file is present, potentially allowing cross-origin data access.", "Remove crossdomain.xml if Flash is not used, or restrict to specific trusted domains."},
		{"/clientaccesspolicy.xml", "cross-domain-access", "Silverlight Client Access Policy", models.SeverityMedium, 5.3, "CWE-942", "A Silverlight client access policy file is present with potentially overly permissive cross-domain rules.", "Remove clientaccesspolicy.xml if Silverlight is not used."},
	}

	baseURL := strings.TrimRight(targetBaseURL, "/")

	for _, dp := range debugPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		fullURL := baseURL + dp.Path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodySample, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyStr := string(bodySample)

			// If no signature required or signature matches
			if dp.Signature == "" || strings.Contains(bodyStr, dp.Signature) {
				dedupHash := models.ComputeDedupHash(dp.Path, "DEBUG_ENDPOINT", models.CategoryInformationLeak)
				findings = append(findings, models.VulnerabilityFinding{
					ID:                uuid.New().String(),
					ScanID:            scanID,
					Title:             dp.Title,
					Description:       dp.Description,
					Remediation:       dp.Remediation,
					Category:          models.CategoryInformationLeak,
					Severity:          dp.Severity,
					CVSSScore:         dp.CVSS,
					CWE:               dp.CWE,
					OWASPCategory:     "A05:2021-Security Misconfiguration",
					ISO27001Control:   "A.8.9 Configuration management, A.8.28 Secure coding",
					NISTControl:       "SP 800-53 CM-7 Least Functionality, SI-11 Error Handling",
					NSACISAGuidance:   "CISA-MISCONFIG-02 Unnecessary Services/Endpoints",
					TargetURL:         fullURL,
					AffectedParameter: dp.Path,
					InjectionContext:  "URL_PATH",
					DedupHash:         dedupHash,
					DiscoveredAt:      time.Now(),
					Proof: &models.HTTPProof{
						RequestURL:      fullURL,
						RequestMethod:   http.MethodGet,
						RequestHeaders:  sanitizer.MaskHeaders(req.Header),
						StatusCode:      resp.StatusCode,
						ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
						ResponseBody:    sanitizer.MaskBody(bodyStr),
					},
				})
			}
		} else {
			resp.Body.Close()
		}
	}

	return findings
}
