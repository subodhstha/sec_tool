package models

import (
	"time"
)

// ScanStatus represents the lifecycle state of a scan job
type ScanStatus string

const (
	StatusPending              ScanStatus = "PENDING"
	StatusRunning              ScanStatus = "RUNNING"
	StatusPausedCircuitBreaker ScanStatus = "PAUSED_CIRCUIT_BREAKER"
	StatusThrottled            ScanStatus = "THROTTLED"
	StatusAborted              ScanStatus = "ABORTED"
	StatusCompleted            ScanStatus = "COMPLETED"
	StatusFailed               ScanStatus = "FAILED"
)

// MacroAction defines the operation performed during an authentication step
type MacroAction string

const (
	ActionNavigate MacroAction = "NAVIGATE"
	ActionType     MacroAction = "TYPE"
	ActionClick    MacroAction = "CLICK"
	ActionWait     MacroAction = "WAIT"
	ActionExtract  MacroAction = "EXTRACT_TOKEN"
)

// MacroStep defines an individual interaction in an authentication sequence (FR-2.1)
type MacroStep struct {
	Order       int         `json:"order"`
	Action      MacroAction `json:"action"`
	Selector    string      `json:"selector,omitempty"`
	Value       string      `json:"value,omitempty"`
	ExtractName string      `json:"extract_name,omitempty"` // e.g. "access_token" or "session_cookie"
	TimeoutMs   int         `json:"timeout_ms,omitempty"`
}

// AuthMacro defines an automated session authentication workflow (FR-2.1)
type AuthMacro struct {
	Type          string            `json:"type"` // "BASIC", "OAUTH2", "BROWSER_MACRO", "BEARER"
	LoginURL      string            `json:"login_url"`
	HeartbeatURL  string            `json:"heartbeat_url"` // FR-2.2 Session monitoring
	StaticHeaders map[string]string `json:"static_headers,omitempty"`
	Steps         []MacroStep       `json:"steps,omitempty"`
	CurrentToken  string            `json:"current_token,omitempty"`
	LastRefresh   time.Time         `json:"last_refresh,omitempty"`
}

// ScanConfig defines runtime safeguards and limits for a scan
type ScanConfig struct {
	SafeMode          bool     `json:"safe_mode"`                   // FR-4.2 Drops destructive verbs & paths
	MaxRPS            int      `json:"max_rps"`                     // FR-4.4 Rate limiting (e.g. 10-50 rps)
	MaxConcurrency    int      `json:"max_concurrency"`             // Max concurrent worker goroutines
	MaxDepth          int      `json:"max_depth"`                   // FR-1.3 Crawl tree-depth ceiling
	VerificationToken string   `json:"verification_token"`          // FR-4.1 Domain verification token
	BaselineLatencyMs int64    `json:"baseline_latency_ms"`         // FR-3.3 & FR-4.4 Baseline for back-off and blind SQLi
	Consecutive5xxCap int      `json:"consecutive_5xx_cap"`         // FR-4.3 Circuit breaker trigger threshold
	LatencyBackoffCap int64    `json:"latency_backoff_cap_ms"`      // Threshold in ms before dynamic throttling
	ActiveFuzzing     bool     `json:"active_fuzzing"`              // True if active injection allowed, false for passive
	PayloadProfile    string   `json:"payload_profile,omitempty"`   // Optional payload safety profile: PASSIVE, LIGHT, STANDARD, AGGRESSIVE, FULL
	ExcludePatterns   []string `json:"exclude_patterns"`            // Regex patterns to strictly bypass
	TargetCategories  []string `json:"target_categories,omitempty"` // Specific payload categories to test
}

// TargetFingerprint captures passive tech-stack detection results (FR-3.1)
type TargetFingerprint struct {
	ServerHeader    string    `json:"server_header,omitempty"`
	Frameworks      []string  `json:"frameworks,omitempty"` // e.g. ["Express", "React", "Spring"]
	Languages       []string  `json:"languages,omitempty"`  // e.g. ["Node.js", "Java", "PHP"]
	Databases       []string  `json:"databases,omitempty"`  // e.g. ["PostgreSQL", "MySQL", "MongoDB"]
	CloudProvider   string    `json:"cloud_provider,omitempty"`
	FingerprintedAt time.Time `json:"fingerprinted_at"`
}

// TargetEndpoint represents an attack surface endpoint discovered by crawling or API ingestion
type TargetEndpoint struct {
	URL        string            `json:"url"`
	Normalized string            `json:"normalized_url"` // FR-1.3 e.g., /api/user/{id}
	Method     string            `json:"method"`
	Parameters []EndpointParam   `json:"parameters,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Source     string            `json:"source"` // "CRAWLER", "OPENAPI", "GRAPHQL"
}

// EndpointParam describes an input parameter to test
type EndpointParam struct {
	Name     string `json:"name"`
	Location string `json:"location"` // "query", "header", "path", "body", "json"
	Value    string `json:"value,omitempty"`
}

// ScanRequest is the external API payload to start a scan
type ScanRequest struct {
	TargetURL   string     `json:"target_url" binding:"required"`
	ScanName    string     `json:"scan_name"`
	Config      ScanConfig `json:"config"`
	Auth        *AuthMacro `json:"auth,omitempty"`
	OpenAPISpec string     `json:"openapi_spec,omitempty"` // Raw YAML or JSON OpenAPI spec
}

// ScanJob is the internal message distributed to scanning workers via RabbitMQ
type ScanJob struct {
	ID          string            `json:"id"`
	TargetURL   string            `json:"target_url"`
	Status      ScanStatus        `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Config      ScanConfig        `json:"config"`
	Auth        *AuthMacro        `json:"auth,omitempty"`
	Fingerprint TargetFingerprint `json:"fingerprint"`
	Stats       ScanStats         `json:"stats"`
}

// ScanStats provides real-time operational and circuit-breaker telemetry
type ScanStats struct {
	TotalRequestsSent    int64   `json:"total_requests_sent"`
	CurrentRPS           float64 `json:"current_rps"`
	AverageLatencyMs     int64   `json:"average_latency_ms"`
	Consecutive5xxCount  int     `json:"consecutive_5xx_count"`
	CircuitBreakerTrips  int     `json:"circuit_breaker_trips"`
	EndpointsDiscovered  int     `json:"endpoints_discovered"`
	EndpointsScanned     int     `json:"endpoints_scanned"`
	VulnerabilitiesFound int     `json:"vulnerabilities_found"`
}
