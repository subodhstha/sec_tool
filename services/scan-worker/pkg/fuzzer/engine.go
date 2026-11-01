package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/scan-worker/pkg/auth"
	"github.com/vyomite/dast/services/scan-worker/pkg/checks"
	"github.com/vyomite/dast/services/scan-worker/pkg/circuitbreaker"
	"github.com/vyomite/dast/services/scan-worker/pkg/filter"
	"github.com/vyomite/dast/services/scan-worker/pkg/payloads"
	"github.com/vyomite/dast/services/scan-worker/pkg/sanitizer"
)

// AttackSimulationEngine coordinates context-aware fuzzing, circuit breakers, and deduplication
type AttackSimulationEngine struct {
	httpClient       *http.Client
	circuitBreaker   *circuitbreaker.CircuitBreaker
	verbEnforcer     *filter.SafeVerbEnforcer
	sessionMgr       *auth.SessionManager
	headerAuditor    *checks.HeaderAuditor
	advHeaderAuditor *checks.AdvancedHeaderAuditor
	cookieAuditor    *checks.CookieAuditor
	infoDisclosure   *checks.InformationDisclosureAuditor
	fileProber       *checks.SensitiveFileProber
	payloadRegistry  *payloads.Registry
	payloadEngine    *payloads.Engine
	oobListenerURL   string
	reqCounter       int64
	findingsMu       sync.Mutex
	dedupRegistry    map[string]*models.VulnerabilityFinding
}

// NewAttackSimulationEngine creates a scanning engine for a target
func NewAttackSimulationEngine(
	cfg models.ScanConfig,
	authMacro *models.AuthMacro,
	oobURL string,
) *AttackSimulationEngine {
	// Initialize payload registry and engine
	reg := payloads.NewRegistry()
	engineCfg := payloads.DefaultEngineConfig()
	engineCfg.OOBCallbackHost = oobURL
	if cfg.SafeMode {
		engineCfg.ActiveFuzzing = false
	} else {
		engineCfg.ActiveFuzzing = true
	}
	if cfg.PayloadProfile != "" {
		engineCfg.Profile = payloads.PayloadProfile(cfg.PayloadProfile)
	}
	if authMacro != nil && len(authMacro.StaticHeaders) > 0 {
		engineCfg.Headers = make(map[string]string, len(authMacro.StaticHeaders))
		for name, value := range authMacro.StaticHeaders {
			engineCfg.Headers[name] = value
		}
	}

	// Uncap the max payloads per parameter so the engine tests ALL payload categories
	// (XSS, SSRF, CSRF, JWT, etc.) instead of stopping at the cap.
	engineCfg.MaxPayloadsPerParam = 0

	if len(cfg.TargetCategories) > 0 {
		cats := make([]payloads.PayloadCategory, 0, len(cfg.TargetCategories))
		for _, c := range cfg.TargetCategories {
			cats = append(cats, payloads.PayloadCategory(c))
		}
		engineCfg.Categories = cats
	}

	payloadEng := payloads.NewEngine(reg, engineCfg)

	return &AttackSimulationEngine{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		circuitBreaker:   circuitbreaker.NewCircuitBreaker(cfg),
		verbEnforcer:     filter.NewSafeVerbEnforcer(cfg.SafeMode, cfg.ExcludePatterns),
		sessionMgr:       auth.NewSessionManager(authMacro),
		headerAuditor:    checks.NewHeaderAuditor(),
		advHeaderAuditor: checks.NewAdvancedHeaderAuditor(),
		cookieAuditor:    checks.NewCookieAuditor(),
		infoDisclosure:   checks.NewInformationDisclosureAuditor(),
		fileProber:       checks.NewSensitiveFileProber(),
		payloadRegistry:  reg,
		payloadEngine:    payloadEng,
		oobListenerURL:   oobURL,
		dedupRegistry:    make(map[string]*models.VulnerabilityFinding),
	}
}

// FingerprintTarget performs passive tech-stack detection (FR-3.1)
func (e *AttackSimulationEngine) FingerprintTarget(ctx context.Context, targetURL string) models.TargetFingerprint {
	fp := models.TargetFingerprint{
		FingerprintedAt: time.Now(),
		Frameworks:      make([]string, 0),
		Languages:       make([]string, 0),
		Databases:       make([]string, 0),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fp
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fp
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	fp.ServerHeader = server
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

	// Passive detection rules
	if strings.Contains(strings.ToLower(server), "nginx") {
		fp.Frameworks = append(fp.Frameworks, "Nginx")
	}
	if strings.Contains(strings.ToLower(server), "apache") {
		fp.Frameworks = append(fp.Frameworks, "Apache")
	}
	if strings.Contains(poweredBy, "express") || strings.Contains(server, "node") {
		fp.Frameworks = append(fp.Frameworks, "Express")
		fp.Languages = append(fp.Languages, "Node.js")
	}
	if strings.Contains(poweredBy, "php") {
		fp.Languages = append(fp.Languages, "PHP")
	}
	if strings.Contains(poweredBy, "asp.net") {
		fp.Frameworks = append(fp.Frameworks, "ASP.NET")
		fp.Languages = append(fp.Languages, "C#")
	}

	// Read small snippet of HTML for React / Vue / Angular detection
	bodySample, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	bodyStr := string(bodySample)

	if strings.Contains(bodyStr, "react-root") || strings.Contains(bodyStr, "_reactListening") {
		fp.Frameworks = append(fp.Frameworks, "React")
	}
	if strings.Contains(bodyStr, "data-v-") || strings.Contains(bodyStr, "id=\"app\"") {
		fp.Frameworks = append(fp.Frameworks, "Vue.js")
	}

	return fp
}

// ScanEndpoint runs safety-aware active injection against a single target endpoint
func (e *AttackSimulationEngine) ScanEndpoint(
	ctx context.Context,
	scanID string,
	endpoint models.TargetEndpoint,
	fp models.TargetFingerprint,
	activeFuzzing bool,
) ([]models.VulnerabilityFinding, error) {
	// FR-4.2 Safe Verb Enforcement: verify this endpoint/method is safe to test
	if allowed, reason := e.verbEnforcer.IsRequestAllowed(endpoint.Method, endpoint.URL); !allowed {
		// Destructive verb or blocked endpoint skipped safely
		return nil, fmt.Errorf("endpoint %s %s skipped: %s", endpoint.Method, endpoint.URL, reason)
	}

	findings := make([]models.VulnerabilityFinding, 0)

	// Always run passive checks (e.g. missing security headers, information disclosure, cookie attributes)
	passiveFindings := e.checkSecurityHeaders(ctx, scanID, endpoint)
	findings = append(findings, passiveFindings...)

	// If the scan is configured for passive mode only, return early before executing active payload injection
	if !activeFuzzing {
		return findings, nil
	}

	// FR-3.1 Context-Aware Injection & FR-3.3 Behavioral Latency Testing
	for _, param := range endpoint.Parameters {
		// 1. Check Circuit Breaker before firing request (FR-4.3, FR-4.4)
		if !e.circuitBreaker.CanExecute() {
			telemetry := e.circuitBreaker.GetTelemetry()
			return findings, fmt.Errorf("scan paused by circuit breaker: state=%s, reason=%s", telemetry.CurrentState, telemetry.TripReason)
		}

		// Rate limiting pacing based on dynamic RPS
		rps := e.circuitBreaker.GetCurrentRPS()
		if rps > 0 {
			time.Sleep(time.Duration(float64(time.Second) / rps))
		}

		// â”€â”€â”€â”€ Payload Engine Injection (All Categories) â”€â”€â”€â”€
		// Map parameter location to injection context
		injCtx := mapEndpointParamToContext(endpoint.Source, param.Location)

		requestHeaders := make(map[string]string)
		for name, value := range e.sessionMgr.GetAuthHeaders() {
			requestHeaders[name] = value
		}
		for name, value := range endpoint.Headers {
			requestHeaders[name] = value
		}
		results := e.payloadEngine.InjectParameterWithHeaders(ctx, endpoint.URL, endpoint.Method, param.Name, injCtx, requestHeaders)
		for _, r := range results {
			if !r.Detected {
				continue
			}

			severity := mapCategoryToSeverity(r.PayloadCategory)
			cvss := mapCategoryToCVSS(r.PayloadCategory)
			dedupHash := models.ComputeDedupHash(r.Parameter, string(r.Context), models.VulnerabilityCategory(r.PayloadCategory))

			finding := &models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             fmt.Sprintf("%s Detected: %s", r.PayloadCategory, r.PayloadName),
				Description:       fmt.Sprintf("%s\n\nEvidence: %s", r.Description, r.Evidence),
				Remediation:       mapCategoryToRemediation(r.PayloadCategory),
				Category:          models.VulnerabilityCategory(r.PayloadCategory),
				Severity:          severity,
				CVSSScore:         cvss,
				CWE:               r.CWE,
				OWASPCategory:     r.OWASPCategory,
				TargetURL:         r.URL,
				AffectedParameter: r.Parameter,
				InjectionContext:  string(r.Context),
				DedupHash:         dedupHash,
				DiscoveredAt:      time.Now(),
				Proof: &models.HTTPProof{
					RequestURL:    r.URL,
					RequestMethod: r.Method,
					StatusCode:    r.ResponseStatus,
					DurationMs:    r.ResponseTimeMs,
				},
			}

			e.recordFinding(finding)
			findings = append(findings, *finding)
		}

		// Legacy: Test for Time-Based Blind SQLi (FR-3.3)
		if sqliFinding := e.testTimeBasedSQLi(ctx, scanID, endpoint, param, fp); sqliFinding != nil {
			e.recordFinding(sqliFinding)
			findings = append(findings, *sqliFinding)
		}

		// Legacy: Test for Blind SSRF via Out-of-Band Listener (FR-3.2)
		if ssrfFinding := e.testBlindSSRF(ctx, scanID, endpoint, param); ssrfFinding != nil {
			e.recordFinding(ssrfFinding)
			findings = append(findings, *ssrfFinding)
		}
	}

	return findings, nil
}

// checkSecurityHeaders audits security response headers, information disclosure, and advanced security posture
func (e *AttackSimulationEngine) checkSecurityHeaders(ctx context.Context, scanID string, endpoint models.TargetEndpoint) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL, nil)
	if err != nil {
		return findings
	}

	// Attach authentication headers if configured (FR-2.1)
	for k, v := range e.sessionMgr.GetAuthHeaders() {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := e.httpClient.Do(req)
	duration := time.Since(start).Milliseconds()
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	atomic.AddInt64(&e.reqCounter, 1)
	e.circuitBreaker.RecordResponse(resp.StatusCode, duration)

	// Check FR-2.2 Heartbeat / 401 Unauthorized handling
	if resp.StatusCode == http.StatusUnauthorized {
		_ = e.sessionMgr.RecoverSession(ctx)
	}

	// Read response body for information disclosure scanning (cap at 256KB)
	bodyBytes := make([]byte, 256*1024)
	n, _ := io.ReadFull(resp.Body, bodyBytes)
	responseBody := string(bodyBytes[:n])

	// ─── 1. Audit Base Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
	headerFindings := e.headerAuditor.AuditHeaders(scanID, endpoint.URL, req, resp)
	for _, f := range headerFindings {
		e.recordFinding(&f)
		findings = append(findings, f)
	}

	// ─── 2. Audit Advanced Security Headers (Permissions-Policy, Cache-Control, CSP Quality, COOP)
	advHeaderFindings := e.advHeaderAuditor.AuditAdvancedHeaders(scanID, endpoint.URL, req, resp)
	for _, f := range advHeaderFindings {
		e.recordFinding(&f)
		findings = append(findings, f)
	}

	// ─── 3. Audit Cookie Attributes (Secure, HttpOnly, SameSite)
	cookieFindings := e.cookieAuditor.AuditCookies(scanID, endpoint.URL, req, resp)
	for _, f := range cookieFindings {
		e.recordFinding(&f)
		findings = append(findings, f)
	}

	// ─── 4. Audit CORS Configuration (Arbitrary Origin reflection + Credentials)
	if corsFinding := e.headerAuditor.AuditCORS(ctx, scanID, endpoint.URL, e.httpClient); corsFinding != nil {
		e.recordFinding(corsFinding)
		findings = append(findings, *corsFinding)
	}

	// ─── 5. Audit Server Version & Technology Disclosure Headers
	versionFindings := e.infoDisclosure.AuditServerVersionHeaders(scanID, endpoint.URL, req, resp)
	for _, f := range versionFindings {
		e.recordFinding(&f)
		findings = append(findings, f)
	}

	// ─── 6. Audit Response Body for Information Disclosure (Stack Traces, Secrets, Credentials)
	if len(responseBody) > 0 {
		infoFindings := e.infoDisclosure.AuditResponseBody(scanID, endpoint.URL, req, resp, responseBody)
		for _, f := range infoFindings {
			e.recordFinding(&f)
			findings = append(findings, f)
		}
	}

	// ─── 7. Audit HTTP Methods (TRACE, PUT, DELETE enumeration)
	methodFindings := e.advHeaderAuditor.AuditHTTPMethods(ctx, scanID, endpoint.URL, e.httpClient)
	for _, f := range methodFindings {
		e.recordFinding(&f)
		findings = append(findings, f)
	}

	return findings
}

// testTimeBasedSQLi tests for time-based blind SQL injection with latency baseline diff (FR-3.3)
func (e *AttackSimulationEngine) testTimeBasedSQLi(
	ctx context.Context,
	scanID string,
	endpoint models.TargetEndpoint,
	param models.EndpointParam,
	fp models.TargetFingerprint,
) *models.VulnerabilityFinding {
	// FR-3.1: Context-aware check: If target is purely static or MongoDB-only, skip SQL syntax
	for _, db := range fp.Databases {
		if strings.Contains(strings.ToLower(db), "mongo") {
			return nil
		}
	}

	telemetry := e.circuitBreaker.GetTelemetry()
	baseline := telemetry.MovingAvgLatencyMs
	if baseline <= 0 {
		baseline = 200
	}

	// 1. Establish baseline control request
	controlURL := endpoint.URL
	reqControl, _ := http.NewRequestWithContext(ctx, http.MethodGet, controlURL, nil)
	for k, v := range e.sessionMgr.GetAuthHeaders() {
		reqControl.Header.Set(k, v)
	}

	startControl := time.Now()
	respControl, err := e.httpClient.Do(reqControl)
	if err != nil {
		return nil
	}
	controlDuration := time.Since(startControl).Milliseconds()
	respControl.Body.Close()
	atomic.AddInt64(&e.reqCounter, 1)
	e.circuitBreaker.RecordResponse(respControl.StatusCode, controlDuration)

	// 2. Fire time delay payload (e.g. 3 second delay)
	delaySeconds := 3
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil
	}

	q := parsed.Query()
	q.Set(param.Name, fmt.Sprintf("%s' OR SLEEP(%d)--", param.Value, delaySeconds))
	parsed.RawQuery = q.Encode()

	testURL := parsed.String()
	reqTest, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	for k, v := range e.sessionMgr.GetAuthHeaders() {
		reqTest.Header.Set(k, v)
	}

	startTest := time.Now()
	respTest, err := e.httpClient.Do(reqTest)
	if err != nil {
		return nil
	}
	testDuration := time.Since(startTest).Milliseconds()
	respTest.Body.Close()
	atomic.AddInt64(&e.reqCounter, 1)
	e.circuitBreaker.RecordResponse(respTest.StatusCode, testDuration)

	// FR-3.3 Behavioral Latency Evaluation:
	// If test duration >= (baseline + delaySeconds*800ms) and significantly higher than control
	expectedMinDelay := int64(delaySeconds * 800)
	if testDuration >= (controlDuration + expectedMinDelay) {
		dedupHash := models.ComputeDedupHash(param.Name, param.Location, models.CategoryTimeBasedBlind)
		return &models.VulnerabilityFinding{
			ID:                uuid.New().String(),
			ScanID:            scanID,
			Title:             "Time-Based Blind SQL Injection",
			Description:       fmt.Sprintf("Parameter '%s' triggered a delayed server response of %dms (baseline %dms), indicating SQL sleep execution.", param.Name, testDuration, controlDuration),
			Remediation:       "Use parameterized SQL queries / prepared statements. Never concatenate user input directly into SQL commands.",
			Category:          models.CategoryTimeBasedBlind,
			Severity:          models.SeverityHigh,
			CVSSScore:         8.5,
			CWE:               "CWE-89",
			OWASPCategory:     "A03:2021-Injection",
			TargetURL:         endpoint.URL,
			AffectedParameter: param.Name,
			InjectionContext:  param.Location,
			DedupHash:         dedupHash,
			DiscoveredAt:      time.Now(),
			Proof: &models.HTTPProof{
				RequestURL:      testURL,
				RequestMethod:   endpoint.Method,
				RequestHeaders:  sanitizer.MaskHeaders(reqTest.Header),
				StatusCode:      respTest.StatusCode,
				ResponseHeaders: sanitizer.MaskHeaders(respTest.Header),
				DurationMs:      testDuration,
			},
		}
	}

	return nil
}

// testBlindSSRF tests out-of-band blind SSRF via correlation listener tokens (FR-3.2)
func (e *AttackSimulationEngine) testBlindSSRF(
	ctx context.Context,
	scanID string,
	endpoint models.TargetEndpoint,
	param models.EndpointParam,
) *models.VulnerabilityFinding {
	if e.oobListenerURL == "" {
		return nil
	}

	// Generate correlation token for OOB verification
	correlationID := uuid.New().String()
	oobCallbackTarget := fmt.Sprintf("%s/callback/%s", strings.TrimRight(e.oobListenerURL, "/"), correlationID)

	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil
	}

	q := parsed.Query()
	q.Set(param.Name, oobCallbackTarget)
	parsed.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	for k, v := range e.sessionMgr.GetAuthHeaders() {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := e.httpClient.Do(req)
	duration := time.Since(start).Milliseconds()
	if err != nil {
		return nil
	}
	resp.Body.Close()

	atomic.AddInt64(&e.reqCounter, 1)
	e.circuitBreaker.RecordResponse(resp.StatusCode, duration)

	// Query OOB listener to check if the correlation token was hit
	time.Sleep(500 * time.Millisecond) // Allow callback propagation
	verifyURL := fmt.Sprintf("%s/api/v1/oob/verify/%s", strings.TrimRight(e.oobListenerURL, "/"), correlationID)
	reqVerify, _ := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	respVerify, err := e.httpClient.Do(reqVerify)
	if err == nil {
		defer respVerify.Body.Close()
		if respVerify.StatusCode == http.StatusOK {
			dedupHash := models.ComputeDedupHash(param.Name, param.Location, models.CategoryBlindSSRF)
			return &models.VulnerabilityFinding{
				ID:                uuid.New().String(),
				ScanID:            scanID,
				Title:             "Blind Server-Side Request Forgery (SSRF)",
				Description:       fmt.Sprintf("Parameter '%s' caused the backend server to make an out-of-band network callback to %s.", param.Name, oobCallbackTarget),
				Remediation:       "Implement strict URL whitelisting, block internal private IP ranges (RFC 1918), and disable unnecessary URL fetchers.",
				Category:          models.CategoryBlindSSRF,
				Severity:          models.SeverityCritical,
				CVSSScore:         9.1,
				CWE:               "CWE-918",
				OWASPCategory:     "A10:2021-Server-Side Request Forgery",
				TargetURL:         endpoint.URL,
				AffectedParameter: param.Name,
				InjectionContext:  param.Location,
				DedupHash:         dedupHash,
				DiscoveredAt:      time.Now(),
				Proof: &models.HTTPProof{
					RequestURL:      parsed.String(),
					RequestMethod:   endpoint.Method,
					RequestHeaders:  sanitizer.MaskHeaders(req.Header),
					StatusCode:      resp.StatusCode,
					ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
					DurationMs:      duration,
				},
			}
		}
	}

	return nil
}

// recordFinding performs deduplication grouping (FR-5.1)
func (e *AttackSimulationEngine) recordFinding(f *models.VulnerabilityFinding) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	if existing, found := e.dedupRegistry[f.DedupHash]; found {
		existing.OccurrencesCount++
		existing.RelatedURLs = append(existing.RelatedURLs, f.TargetURL)
	} else {
		f.OccurrencesCount = 1
		f.RelatedURLs = []string{f.TargetURL}
		e.dedupRegistry[f.DedupHash] = f
	}
}

// ProbeSensitiveFiles tests for exposed root files (50+ paths: VCS, env, configs, backups, keys, logs, etc.)
func (e *AttackSimulationEngine) ProbeSensitiveFiles(ctx context.Context, scanID, targetURL string) []models.VulnerabilityFinding {
	findings := e.fileProber.ProbeRootPaths(ctx, scanID, targetURL, e.httpClient)
	for i := range findings {
		e.recordFinding(&findings[i])
	}
	return findings
}

// ProbeDebugEndpoints tests for exposed debug/admin endpoints (actuator, pprof, Swagger, etc.)
func (e *AttackSimulationEngine) ProbeDebugEndpoints(ctx context.Context, scanID, targetURL string) []models.VulnerabilityFinding {
	findings := e.infoDisclosure.AuditDebugEndpoints(ctx, scanID, targetURL, e.httpClient)
	for i := range findings {
		e.recordFinding(&findings[i])
	}
	return findings
}

// GetCircuitBreaker returns the engine circuit breaker
func (e *AttackSimulationEngine) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	return e.circuitBreaker
}

// GetTotalRequests returns the count of requests sent
func (e *AttackSimulationEngine) GetTotalRequests() int64 {
	return atomic.LoadInt64(&e.reqCounter)
}

// GetPayloadRegistry returns the payload registry for inspection
func (e *AttackSimulationEngine) GetPayloadRegistry() *payloads.Registry {
	return e.payloadRegistry
}

// mapParamLocationToContext converts endpoint parameter locations to payload injection contexts
func mapParamLocationToContext(location string) payloads.InjectionContext {
	switch strings.ToLower(location) {
	case "query", "url_query", "url":
		return payloads.ContextURLQuery
	case "path", "url_path":
		return payloads.ContextURLPath
	case "body", "form", "form_body":
		return payloads.ContextFormBody
	case "json", "json_body":
		return payloads.ContextJSONBody
	case "xml", "xml_body":
		return payloads.ContextXMLBody
	case "header", "http_header":
		return payloads.ContextHTTPHeader
	case "cookie":
		return payloads.ContextCookie
	default:
		return payloads.ContextURLQuery
	}
}

func mapEndpointParamToContext(source, location string) payloads.InjectionContext {
	if strings.EqualFold(source, "GRAPHQL") {
		return payloads.ContextGraphQL
	}
	return mapParamLocationToContext(location)
}

// mapCategoryToSeverity maps payload categories to vulnerability severity levels
func mapCategoryToSeverity(cat payloads.PayloadCategory) models.VulnerabilitySeverity {
	switch cat {
	case payloads.PayloadSQLi, payloads.PayloadCommandInjection, payloads.PayloadXXE, payloads.PayloadSSTI, payloads.PayloadNoSQLi,
		payloads.PayloadInsecureDeserial, payloads.PayloadFileUpload:
		return models.SeverityCritical
	case payloads.PayloadSSRF, payloads.PayloadXSS, payloads.PayloadPathTraversal, payloads.PayloadLDAPi,
		payloads.PayloadJWT, payloads.PayloadAuthBypass, payloads.PayloadPrototypePollut, payloads.PayloadIDOR,
		payloads.PayloadFileInclusion:
		return models.SeverityHigh
	case payloads.PayloadCRLF, payloads.PayloadHeaderInjection, payloads.PayloadHostHeader,
		payloads.PayloadCORS, payloads.PayloadCSRF, payloads.PayloadRaceCondition, payloads.PayloadGraphQL,
		payloads.PayloadWebSocket:
		return models.SeverityMedium
	case payloads.PayloadOpenRedirect:
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

// mapCategoryToCVSS maps payload categories to baseline CVSS v3.1 scores
func mapCategoryToCVSS(cat payloads.PayloadCategory) float64 {
	switch cat {
	case payloads.PayloadSQLi, payloads.PayloadCommandInjection, payloads.PayloadInsecureDeserial, payloads.PayloadFileUpload:
		return 9.8
	case payloads.PayloadXXE, payloads.PayloadSSTI:
		return 9.1
	case payloads.PayloadSSRF, payloads.PayloadAuthBypass:
		return 8.6
	case payloads.PayloadJWT, payloads.PayloadIDOR, payloads.PayloadPrototypePollut:
		return 8.1
	case payloads.PayloadFileInclusion:
		return 8.1
	case payloads.PayloadXSS, payloads.PayloadPathTraversal:
		return 7.5
	case payloads.PayloadNoSQLi, payloads.PayloadLDAPi:
		return 8.1
	case payloads.PayloadCORS, payloads.PayloadRaceCondition:
		return 6.5
	case payloads.PayloadCRLF, payloads.PayloadHeaderInjection, payloads.PayloadHostHeader,
		payloads.PayloadCSRF, payloads.PayloadGraphQL, payloads.PayloadWebSocket:
		return 5.4
	case payloads.PayloadOpenRedirect:
		return 4.3
	default:
		return 5.0
	}
}

// mapCategoryToRemediation provides OWASP-aligned remediation guidance per category
func mapCategoryToRemediation(cat payloads.PayloadCategory) string {
	remediations := map[payloads.PayloadCategory]string{
		payloads.PayloadSQLi:             "Use parameterized queries / prepared statements. Apply input validation. Never concatenate user input into SQL. Enforce least-privilege database accounts. [OWASP A03:2021]",
		payloads.PayloadXSS:              "Apply context-aware output encoding. Use Content-Security-Policy headers. Sanitize HTML input with allowlist-based libraries. Avoid innerHTML/document.write. [OWASP A03:2021]",
		payloads.PayloadCommandInjection: "Avoid system/exec calls with user input. Use language-native APIs. Apply strict input validation and allowlisting. Use AppArmor/SELinux for defense-in-depth. [OWASP A03:2021]",
		payloads.PayloadSSRF:             "Implement strict URL allowlisting. Block internal IP ranges (RFC 1918). Disable unnecessary URL fetch protocols. Use network segmentation. [OWASP A10:2021]",
		payloads.PayloadXXE:              "Disable external entity processing in XML parsers. Use JSON where possible. Configure DTD processing to be disabled by default. [OWASP A05:2021]",
		payloads.PayloadPathTraversal:    "Use allowlisted file paths. Canonicalize and validate file paths. Never use user input directly in file operations. Apply chroot/sandboxing. [OWASP A01:2021]",
		payloads.PayloadSSTI:             "Never pass user input directly into template engines. Use sandboxed template contexts. Apply strict input validation. [OWASP A03:2021]",
		payloads.PayloadCRLF:             "Strip or encode CR/LF characters from user input before including in HTTP headers. Use framework-provided header-setting APIs. [OWASP A03:2021]",
		payloads.PayloadHeaderInjection:  "Validate and sanitize all header values. Use framework header APIs that prevent injection. [OWASP A03:2021]",
		payloads.PayloadHostHeader:       "Configure web server to reject requests with unrecognized Host headers. Use allowlisted hosts. Never trust Host header for security decisions. [OWASP A05:2021]",
		payloads.PayloadOpenRedirect:     "Validate redirect URLs against an allowlist of trusted domains. Use relative paths. Never pass full URLs in redirect parameters. [OWASP A01:2021]",
		payloads.PayloadLDAPi:            "Use parameterized LDAP queries. Escape special LDAP characters. Apply input validation. [OWASP A03:2021]",
		payloads.PayloadNoSQLi:           "Use parameterized queries for NoSQL databases. Validate input types strictly. Disable server-side JavaScript execution. [OWASP A03:2021]",
		payloads.PayloadCORS:             "Do not reflect untrusted Origin headers. Maintain an explicit allowlist of authorized origins. Never combine wildcard (*) with Allow-Credentials: true. [OWASP A01:2021]",
		payloads.PayloadCSRF:             "Implement synchronizer tokens (CSRF tokens) on all state-changing forms. Use SameSite cookie attributes. Validate the Origin/Referer header. [OWASP A01:2021]",
		payloads.PayloadIDOR:             "Implement proper authorization checks on all object access. Use indirect references (UUIDs). Never rely solely on client-supplied IDs. [OWASP A01:2021]",
		payloads.PayloadJWT:              "Validate JWT algorithm against a server-side allowlist. Never accept 'none' algorithm. Use strong asymmetric keys. Verify all claims (exp, iss, aud). [OWASP A07:2021]",
		payloads.PayloadAuthBypass:       "Implement consistent authentication at the reverse proxy and application layers. Validate all URL path normalizations. Do not trust X-Forwarded-* headers. [OWASP A07:2021]",
		payloads.PayloadInsecureDeserial: "Never deserialize untrusted data. Use integrity checks (HMAC) on serialized objects. Implement type constraints and allowlists. Monitor deserialization endpoints. [OWASP A08:2021]",
		payloads.PayloadPrototypePollut:  "Freeze Object.prototype. Use Map instead of plain objects for dynamic keys. Validate and sanitize JSON input against __proto__ and constructor keys. [OWASP A03:2021]",
		payloads.PayloadFileUpload:       "Validate file type by magic bytes, not just extension. Use randomized filenames. Store uploads outside the web root. Scan uploads with antivirus. [OWASP A04:2021]",
		payloads.PayloadFileInclusion:    "Avoid including user-controlled paths. Allowlist files, canonicalize paths, disable remote includes, and isolate application-readable files. [OWASP A03:2021]",
		payloads.PayloadGraphQL:          "Disable introspection in production. Implement query depth/complexity limits. Require authentication. Use persisted queries. [OWASP A03:2021]",
		payloads.PayloadWebSocket:        "Validate the Origin header on WebSocket upgrade requests. Apply authentication to WebSocket connections. Sanitize all WebSocket message data. [OWASP A01:2021]",
		payloads.PayloadRaceCondition:    "Use database-level locking or atomic operations for critical resources. Implement idempotency keys. Use pessimistic locking for financial operations. [OWASP A04:2021]",
	}

	if r, ok := remediations[cat]; ok {
		return r
	}
	return "Apply input validation, output encoding, and follow OWASP secure coding guidelines."
}
