package payloads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EngineConfig configures the payload injection engine behavior.
type EngineConfig struct {
	// Profile optionally applies one of the built-in payload safety profiles.
	// Empty preserves the legacy ActiveFuzzing behavior.
	Profile PayloadProfile

	// ActiveFuzzing enables payloads marked as non-safe (time-based, RCE, etc.)
	ActiveFuzzing bool

	// MaxPayloadsPerParam caps the number of payloads tested per parameter
	MaxPayloadsPerParam int

	// RequestTimeout is the HTTP timeout for each injected request
	RequestTimeout time.Duration

	// TimeDeltaThreshold is the minimum response time increase to confirm time-based detection
	TimeDeltaThreshold time.Duration

	// BaselineResponseMs is the measured average response time for the target
	BaselineResponseMs int

	// ContentDiffThresholdBytes is the minimum body-length delta for content-diff detection.
	ContentDiffThresholdBytes int

	// UserAgent is the scanner's HTTP User-Agent header
	UserAgent string

	// Headers are headers applied to every injected request, such as auth tokens.
	Headers map[string]string

	// OOBCallbackHost is the out-of-band listener hostname for OOB detection
	OOBCallbackHost string

	// TargetStack hints (e.g., ["MySQL", "PHP", "Linux"]) for context-aware payload selection
	TargetStack []string

	// Categories limits scanning to specific payload categories (empty = all)
	Categories []PayloadCategory

	// MaxConcurrentRequests limits parallel injection requests
	MaxConcurrentRequests int
}

// DefaultEngineConfig returns a production-safe default configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		ActiveFuzzing:             false,
		MaxPayloadsPerParam:       50,
		RequestTimeout:            15 * time.Second,
		TimeDeltaThreshold:        4 * time.Second,
		BaselineResponseMs:        500,
		ContentDiffThresholdBytes: 32,
		UserAgent:                 "Vyomite-DAST/1.0",
		MaxConcurrentRequests:     5,
	}
}

// InjectionResult captures the outcome of a single payload test.
type InjectionResult struct {
	PayloadID       string           `json:"payload_id"`
	PayloadCategory PayloadCategory  `json:"payload_category"`
	PayloadName     string           `json:"payload_name"`
	Parameter       string           `json:"parameter"`
	InjectedValue   string           `json:"injected_value"`
	Context         InjectionContext `json:"context"`
	URL             string           `json:"url"`
	Method          string           `json:"method"`

	// Detection
	Detected        bool            `json:"detected"`
	DetectionMethod DetectionMethod `json:"detection_method"`
	Evidence        string          `json:"evidence,omitempty"`
	ResponseStatus  int             `json:"response_status"`
	ResponseTimeMs  int64           `json:"response_time_ms"`
	ResponseLength  int             `json:"response_length"`

	// Compliance
	CWE           string `json:"cwe"`
	OWASPCategory string `json:"owasp_category"`
	Description   string `json:"description"`

	// Deduplication
	DedupHash string `json:"dedup_hash"`
}

// Engine orchestrates payload injection, HTTP execution, and response analysis.
type Engine struct {
	registry *Registry
	config   EngineConfig
	client   *http.Client
	seen     map[string]bool // dedup hashes
	seenMu   sync.Mutex
}

// NewEngine creates a payload injection engine with the given registry and config.
func NewEngine(registry *Registry, config EngineConfig) *Engine {
	return &Engine{
		registry: registry,
		config:   config,
		client: &http.Client{
			Timeout: config.RequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		seen: make(map[string]bool),
	}
}

// InjectParameter tests a single parameter on a URL with all matching payloads.
// It returns a slice of confirmed injection results.
func (e *Engine) InjectParameter(ctx context.Context, targetURL, method, paramName string, injCtx InjectionContext) []InjectionResult {
	return e.injectParameter(ctx, targetURL, method, paramName, injCtx, nil)
}

// InjectParameterWithHeaders tests a parameter while preserving endpoint-specific headers.
func (e *Engine) InjectParameterWithHeaders(ctx context.Context, targetURL, method, paramName string, injCtx InjectionContext, headers map[string]string) []InjectionResult {
	return e.injectParameter(ctx, targetURL, method, paramName, injCtx, headers)
}

func (e *Engine) injectParameter(ctx context.Context, targetURL, method, paramName string, injCtx InjectionContext, requestHeaders map[string]string) []InjectionResult {
	// Build filter options
	opts := FilterOptions{
		Contexts: []InjectionContext{injCtx},
		SafeOnly: !e.config.ActiveFuzzing,
	}
	if len(e.config.Categories) > 0 {
		opts.Categories = e.config.Categories
	}
	if len(e.config.TargetStack) > 0 {
		opts.TargetStack = e.config.TargetStack
	}

	payloads := e.registry.FilterPayloads(opts)
	maxPayloadsPerParam := e.config.MaxPayloadsPerParam
	if e.config.Profile != "" {
		profile, ok := DefaultProfiles()[e.config.Profile]
		if !ok {
			return nil
		}
		filtered := payloads[:0]
		for _, payload := range payloads {
			if profileAllowsPayload(payload, profile) {
				filtered = append(filtered, payload)
			}
		}
		payloads = filtered
		if profile.MaxPayloadsPerParam > 0 && (maxPayloadsPerParam <= 0 || profile.MaxPayloadsPerParam < maxPayloadsPerParam) {
			maxPayloadsPerParam = profile.MaxPayloadsPerParam
		}
	}

	// Cap payloads per parameter
	if maxPayloadsPerParam > 0 && len(payloads) > maxPayloadsPerParam {
		payloads = payloads[:maxPayloadsPerParam]
	}

	var baseline *baselineResponse
	for _, payload := range payloads {
		if payload.Detection == DetectContentDiff || payload.Detection == DetectStatusCode {
			baseline = e.captureBaseline(ctx, targetURL, method, requestHeaders)
			break
		}
	}

	workerCount := e.config.MaxConcurrentRequests
	if workerCount <= 0 || workerCount > len(payloads) {
		workerCount = len(payloads)
	}
	if workerCount <= 1 {
		workerCount = 1
	}

	type payloadResult struct {
		index    int
		result   InjectionResult
		detected bool
	}
	jobs := make(chan int)
	completed := make(chan payloadResult, len(payloads))
	var workers sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				payload := payloads[index]
				value := payload.Value
				if e.config.OOBCallbackHost != "" {
					value = strings.ReplaceAll(value, "VYOMITE_OOB_HOST", e.config.OOBCallbackHost)
				}
				hash := computePayloadDedupHash(targetURL, method, paramName, injCtx, payload.Category, payload.ID)
				e.seenMu.Lock()
				alreadySeen := e.seen[hash]
				e.seenMu.Unlock()
				if alreadySeen {
					continue
				}

				result := e.executeInjection(ctx, targetURL, method, paramName, value, injCtx, payload, baseline, requestHeaders)
				result.DedupHash = hash
				if result.Detected {
					e.seenMu.Lock()
					e.seen[hash] = true
					e.seenMu.Unlock()
					log.Printf("[PAYLOAD-HIT] %s on %s param=%s payload=%s", payload.Category, targetURL, paramName, payload.ID)
				}
				completed <- payloadResult{index: index, result: result, detected: result.Detected}
			}
		}()
	}
dispatch:
	for index := range payloads {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	close(completed)

	results := make([]InjectionResult, 0, len(payloads))
	ordered := make([]*payloadResult, len(payloads))
	for item := range completed {
		if item.detected {
			copy := item
			ordered[item.index] = &copy
		}
	}
	for _, item := range ordered {
		if item != nil {
			results = append(results, item.result)
		}
	}
	return results
}

func profileAllowsPayload(payload Payload, profile ProfileConfig) bool {
	if len(profile.AllowedSeverity) > 0 && !containsSeverity(profile.AllowedSeverity, payload.Severity) {
		return false
	}
	if !profile.AllowActive && !payload.SafeMode {
		return false
	}
	if !profile.AllowTimeBased && payload.Detection == DetectTimeDelta {
		return false
	}
	if !profile.AllowOOB && (payload.Detection == DetectOOBCallback || payload.Detection == DetectDNSLookup) {
		return false
	}
	if profile.Profile == ProfileLight && payload.Detection != DetectReflection && payload.Detection != DetectErrorPattern {
		return false
	}
	if len(profile.Categories) > 0 && !containsCategory(profile.Categories, payload.Category) {
		return false
	}
	for _, excluded := range profile.ExcludeTags {
		for _, tag := range payload.Tags {
			if strings.EqualFold(excluded, tag) {
				return false
			}
		}
	}
	return true
}

func containsSeverity(severities []SeverityLevel, severity SeverityLevel) bool {
	for _, candidate := range severities {
		if candidate == severity {
			return true
		}
	}
	return false
}

func containsCategory(categories []PayloadCategory, category PayloadCategory) bool {
	for _, candidate := range categories {
		if candidate == category {
			return true
		}
	}
	return false
}

type baselineResponse struct {
	statusCode int
	length     int
	location   string
}

func (e *Engine) captureBaseline(ctx context.Context, targetURL, method string, requestHeaders map[string]string) *baselineResponse {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", e.config.UserAgent)
	e.applyHeaders(req, requestHeaders)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}
	return &baselineResponse{statusCode: resp.StatusCode, length: len(body), location: resp.Header.Get("Location")}
}

// executeInjection sends the injected HTTP request and analyzes the response.
func (e *Engine) executeInjection(ctx context.Context, targetURL, method, paramName, value string, injCtx InjectionContext, payload Payload, baseline *baselineResponse, requestHeaders map[string]string) InjectionResult {
	result := InjectionResult{
		PayloadID:       payload.ID,
		PayloadCategory: payload.Category,
		PayloadName:     payload.Name,
		Parameter:       paramName,
		InjectedValue:   value,
		Context:         injCtx,
		URL:             targetURL,
		Method:          method,
		DetectionMethod: payload.Detection,
		CWE:             payload.CWE,
		OWASPCategory:   payload.OWASPCategory,
		Description:     payload.Description,
	}

	// Build injected URL
	injectedURL, body := e.buildInjectedRequest(targetURL, paramName, value, injCtx)
	contentType := ""
	if injCtx == ContextMultipart {
		body, contentType = multipartPayload(paramName, value)
	}

	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, injectedURL, reqBody)
	if err != nil {
		return result
	}

	req.Header.Set("User-Agent", e.config.UserAgent)
	e.applyHeaders(req, requestHeaders)
	if injCtx == ContextFormBody {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if injCtx == ContextJSONBody || injCtx == ContextGraphQL {
		req.Header.Set("Content-Type", "application/json")
	} else if injCtx == ContextXMLBody {
		req.Header.Set("Content-Type", "application/xml")
	} else if injCtx == ContextMultipart {
		req.Header.Set("Content-Type", contentType)
	}

	if injCtx == ContextHTTPHeader && paramName != "" {
		req.Header.Set(paramName, value)
	}
	if injCtx == ContextCookie && paramName != "" {
		req.AddCookie(&http.Cookie{Name: paramName, Value: value})
	}

	// Host header injection
	if injCtx == ContextHTTPHeader && payload.Category == PayloadHostHeader {
		req.Header.Set("X-Forwarded-Host", value)
		req.Header.Set("X-Forwarded-For", value)
	}

	// Execute and measure
	start := time.Now()
	resp, err := e.client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		// Timeout could indicate time-based detection
		if ctx.Err() == nil && payload.Detection == DetectTimeDelta {
			result.ResponseTimeMs = elapsed.Milliseconds()
			if elapsed > e.config.TimeDeltaThreshold {
				result.Detected = true
				result.Evidence = fmt.Sprintf("Response delayed %dms (threshold: %dms)", elapsed.Milliseconds(), e.config.TimeDeltaThreshold.Milliseconds())
			}
		}
		return result
	}
	defer resp.Body.Close()

	result.ResponseStatus = resp.StatusCode
	result.ResponseTimeMs = elapsed.Milliseconds()

	// Read response body (cap at 512KB)
	bodyBytes := make([]byte, 512*1024)
	n, _ := io.ReadFull(resp.Body, bodyBytes)
	responseBody := string(bodyBytes[:n])
	result.ResponseLength = n

	// Analyze based on detection method
	switch payload.Detection {
	case DetectReflection:
		if payload.DetectSignature != "" {
			re, err := regexp.Compile(payload.DetectSignature)
			matchedBody := responseBody
			matchedRe := re
			if err == nil && !re.MatchString(matchedBody) {
				headerRe, headerErr := regexp.Compile("(?i)" + payload.DetectSignature)
				headerText := responseHeadersText(resp.Header)
				if headerErr == nil && headerRe.MatchString(headerText) {
					matchedBody = headerText
					matchedRe = headerRe
				}
			}
			if err == nil && matchedRe.MatchString(matchedBody) {
				result.Detected = true
				loc := matchedRe.FindStringIndex(matchedBody)
				if loc != nil {
					start := loc[0]
					end := loc[1]
					if end-start > 200 {
						end = start + 200
					}
					result.Evidence = fmt.Sprintf("Pattern matched: %s", matchedBody[start:end])
				}
			}
		}

	case DetectErrorPattern:
		if payload.DetectSignature != "" {
			re, err := regexp.Compile(payload.DetectSignature)
			if err == nil && re.MatchString(responseBody) {
				result.Detected = true
				loc := re.FindStringIndex(responseBody)
				if loc != nil {
					// Capture surrounding context
					ctxStart := loc[0] - 50
					if ctxStart < 0 {
						ctxStart = 0
					}
					ctxEnd := loc[1] + 50
					if ctxEnd > len(responseBody) {
						ctxEnd = len(responseBody)
					}
					result.Evidence = fmt.Sprintf("Error pattern: ...%s...", responseBody[ctxStart:ctxEnd])
				}
			}
		}

	case DetectTimeDelta:
		threshold := e.config.TimeDeltaThreshold
		if payload.DelayMs > 0 {
			// Use payload-specific delay threshold (80% of expected)
			threshold = time.Duration(float64(payload.DelayMs)*0.8) * time.Millisecond
		}
		if elapsed > threshold {
			result.Detected = true
			result.Evidence = fmt.Sprintf("Response time %dms exceeds threshold %dms (baseline: %dms)",
				elapsed.Milliseconds(), threshold.Milliseconds(), e.config.BaselineResponseMs)
		}

	case DetectStatusCode:
		if baseline != nil && responseDiffersFromBaseline(resp.StatusCode, n, resp.Header.Get("Location"), baseline, e.config.ContentDiffThresholdBytes) {
			result.Detected = true
			result.Evidence = fmt.Sprintf("Response differs from baseline: baseline status=%d location=%q length=%d, response status=%d location=%q length=%d", baseline.statusCode, baseline.location, baseline.length, resp.StatusCode, resp.Header.Get("Location"), n)
		}

	case DetectHeaderInject:
		if payload.DetectSignature != "" {
			re, err := regexp.Compile(payload.DetectSignature)
			headerText := responseHeadersText(resp.Header)
			if err == nil && re.MatchString(headerText) {
				result.Detected = true
				result.Evidence = fmt.Sprintf("Response header matched: %s", re.FindString(headerText))
			}
		}

	case DetectContentDiff:
		if baseline != nil {
			if responseDiffersFromBaseline(resp.StatusCode, n, "", baseline, e.config.ContentDiffThresholdBytes) {
				result.Detected = true
				result.Evidence = fmt.Sprintf("Content changed: baseline status=%d length=%d, response status=%d length=%d", baseline.statusCode, baseline.length, resp.StatusCode, n)
			}
		}

	case DetectOOBCallback:
		result.Evidence = "OOB callback detection requires external listener â€” payload delivered"
	}

	return result
}

func responseDiffersFromBaseline(statusCode, length int, location string, baseline *baselineResponse, threshold int) bool {
	if baseline == nil {
		return false
	}
	if statusCode != baseline.statusCode {
		return true
	}
	if location != "" && location != baseline.location {
		return true
	}
	if threshold <= 0 {
		threshold = 32
	}
	lengthDelta := length - baseline.length
	if lengthDelta < 0 {
		lengthDelta = -lengthDelta
	}
	return lengthDelta >= threshold
}

func (e *Engine) applyHeaders(req *http.Request, requestHeaders map[string]string) {
	for name, value := range e.config.Headers {
		req.Header.Set(name, value)
	}
	for name, value := range requestHeaders {
		req.Header.Set(name, value)
	}
}

func responseHeadersText(headers http.Header) string {
	var builder strings.Builder
	for name, values := range headers {
		for _, value := range values {
			builder.WriteString(name)
			builder.WriteString(": ")
			builder.WriteString(value)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

// buildInjectedRequest constructs the URL and body with the payload injected.
func (e *Engine) buildInjectedRequest(targetURL, paramName, value string, injCtx InjectionContext) (string, string) {
	switch injCtx {
	case ContextURLQuery:
		u, err := url.Parse(targetURL)
		if err != nil {
			return targetURL, ""
		}
		q := u.Query()
		q.Set(paramName, value)
		u.RawQuery = q.Encode()
		return u.String(), ""

	case ContextURLPath:
		u, err := url.Parse(targetURL)
		if err != nil {
			return targetURL, ""
		}
		placeholder := "{" + paramName + "}"
		if strings.Contains(u.Path, placeholder) {
			u.Path = strings.Replace(u.Path, placeholder, value, 1)
		} else {
			u.Path = strings.TrimRight(u.Path, "/") + "/" + value
		}
		return u.String(), ""

	case ContextFormBody:
		return targetURL, fmt.Sprintf("%s=%s", url.QueryEscape(paramName), url.QueryEscape(value))

	case ContextJSONBody:
		return targetURL, jsonPayload(paramName, value)

	case ContextGraphQL:
		return targetURL, jsonPayload(paramName, value)

	case ContextXMLBody:
		return targetURL, value // XXE payloads are complete XML documents

	case ContextHTTPHeader:
		return targetURL, ""

	case ContextCookie:
		return targetURL, ""

	case ContextMultipart:
		return targetURL, ""

	default:
		return targetURL, ""
	}
}

func multipartPayload(fieldName, value string) (string, string) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	filename := value
	if filename == "" {
		filename = "vyomite-payload.bin"
	}
	part, err := writer.CreateFormFile(fieldName, filename)
	if err == nil {
		_, _ = part.Write([]byte(value))
	}
	_ = writer.Close()
	return buffer.String(), writer.FormDataContentType()
}

func jsonPayload(paramName, value string) string {
	trimmed := strings.TrimSpace(value)
	if paramName == "" || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return value
	}

	encodedName, err := json.Marshal(paramName)
	if err != nil {
		return value
	}
	encodedValue, err := json.Marshal(value)
	if err != nil {
		return value
	}
	return fmt.Sprintf(`{%s:%s}`, encodedName, encodedValue)
}

// computePayloadDedupHash generates a deduplication hash for this injection combination.
func computePayloadDedupHash(targetURL, method, paramName string, ctx InjectionContext, category PayloadCategory, payloadID string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s:%s:%s", targetURL, method, paramName, ctx, category, payloadID)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:16])
}
