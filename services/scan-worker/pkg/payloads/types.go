package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Vyomite DAST â€“ Enterprise Payload Configuration System
// Sourced from: PayloadsAllTheThings (swisskyrepo) + OWASP Testing Guide
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// PayloadCategory classifies injection vector families
type PayloadCategory string

const (
	CatSQLi             PayloadCategory = "SQLI"
	CatXSS              PayloadCategory = "XSS"
	CatSSRF             PayloadCategory = "SSRF"
	CatXXE              PayloadCategory = "XXE"
	CatCMDi             PayloadCategory = "CMDI"
	CatPathTraversal    PayloadCategory = "PATH_TRAVERSAL"
	CatLDAPi            PayloadCategory = "LDAPI"
	CatSSTI             PayloadCategory = "SSTI"
	CatHeaderInjection  PayloadCategory = "HEADER_INJECTION"
	CatOpenRedirect     PayloadCategory = "OPEN_REDIRECT"
	CatHostHeader       PayloadCategory = "HOST_HEADER"
	CatCRLF             PayloadCategory = "CRLF"
	CatNoSQLi           PayloadCategory = "NOSQLI"
	CatCSRF             PayloadCategory = "CSRF"
	CatIDOR             PayloadCategory = "IDOR"
	CatInsecureDeserial PayloadCategory = "INSECURE_DESERIALIZATION"
	CatPrototypePollut  PayloadCategory = "PROTOTYPE_POLLUTION"
	CatGraphQL          PayloadCategory = "GRAPHQL"
	CatWebSocket        PayloadCategory = "WEBSOCKET"
	CatCORS             PayloadCategory = "CORS"
	CatJWT              PayloadCategory = "JWT"
	CatAuthBypass       PayloadCategory = "AUTH_BYPASS"
	CatFileUpload       PayloadCategory = "FILE_UPLOAD"
	CatFileInclusion    PayloadCategory = "FILE_INCLUSION"
	CatRaceCondition    PayloadCategory = "RACE_CONDITION"
)

// InjectionContext describes where the payload is delivered
type InjectionContext string

const (
	CtxURLQuery   InjectionContext = "URL_QUERY"
	CtxURLPath    InjectionContext = "URL_PATH"
	CtxFormBody   InjectionContext = "FORM_BODY"
	CtxJSONBody   InjectionContext = "JSON_BODY"
	CtxXMLBody    InjectionContext = "XML_BODY"
	CtxHTTPHeader InjectionContext = "HTTP_HEADER"
	CtxCookie     InjectionContext = "COOKIE"
	CtxFragment   InjectionContext = "FRAGMENT"
	CtxMultipart  InjectionContext = "MULTIPART"
	CtxWebSocket  InjectionContext = "WEBSOCKET"
	CtxGraphQL    InjectionContext = "GRAPHQL"
)

// DetectionMethod defines how the scanner verifies a hit
type DetectionMethod string

const (
	DetectReflection   DetectionMethod = "REFLECTION"
	DetectTimeDelta    DetectionMethod = "TIME_DELTA"
	DetectErrorPattern DetectionMethod = "ERROR_PATTERN"
	DetectStatusCode   DetectionMethod = "STATUS_CODE"
	DetectOOBCallback  DetectionMethod = "OOB_CALLBACK"
	DetectContentDiff  DetectionMethod = "CONTENT_DIFF"
	DetectDOMExec      DetectionMethod = "DOM_EXECUTION"
	DetectHeaderInject DetectionMethod = "HEADER_INJECTION"
	DetectDNSLookup    DetectionMethod = "DNS_LOOKUP"
	DetectRedirect     DetectionMethod = "REDIRECT"
	DetectBehavioral   DetectionMethod = "BEHAVIORAL"
)

// Severity levels aligned with CVSS v3.1
type SeverityLevel string

const (
	SevInfo     SeverityLevel = "INFO"
	SevLow      SeverityLevel = "LOW"
	SevMedium   SeverityLevel = "MEDIUM"
	SevHigh     SeverityLevel = "HIGH"
	SevCritical SeverityLevel = "CRITICAL"
)

// Technique describes the sub-technique within a category
type Technique string

const (
	// SQLi techniques
	TechErrorBased      Technique = "ERROR_BASED"
	TechBooleanBlind    Technique = "BOOLEAN_BLIND"
	TechTimeBlind       Technique = "TIME_BLIND"
	TechUnionBased      Technique = "UNION_BASED"
	TechStackedQuery    Technique = "STACKED_QUERY"
	TechOOBExfil        Technique = "OOB_EXFIL"
	TechAuthBypass      Technique = "AUTH_BYPASS"
	TechDBMSFingerprint Technique = "DBMS_FINGERPRINT"
	TechWAFBypass       Technique = "WAF_BYPASS"
	TechPolyglot        Technique = "POLYGLOT"

	// XSS techniques
	TechReflectedXSS   Technique = "REFLECTED"
	TechStoredXSS      Technique = "STORED"
	TechDOMXSS         Technique = "DOM_BASED"
	TechEventHandler   Technique = "EVENT_HANDLER"
	TechAttributeBreak Technique = "ATTR_BREAKOUT"
	TechJSProtocol     Technique = "JS_PROTOCOL"
	TechTemplateXSS    Technique = "TEMPLATE_XSS"
	TechBlindXSS       Technique = "BLIND_XSS"
	TechMutationXSS    Technique = "MUTATION_XSS"

	// Generic
	TechClassic      Technique = "CLASSIC"
	TechEncoded      Technique = "ENCODED"
	TechFilterBypass Technique = "FILTER_BYPASS"
	TechOOB          Technique = "OOB"
	TechProbe        Technique = "PROBE"
	TechExfiltration Technique = "EXFILTRATION"

	// CSRF techniques
	TechTokenMissing   Technique = "TOKEN_MISSING"
	TechMethodOverride Technique = "METHOD_OVERRIDE"
	TechContentType    Technique = "CONTENT_TYPE"

	// IDOR techniques
	TechSequentialID   Technique = "SEQUENTIAL_ID"
	TechEncodedID      Technique = "ENCODED_ID"
	TechParamTampering Technique = "PARAM_TAMPERING"

	// Insecure Deserialization techniques
	TechJavaDeserial   Technique = "JAVA_DESERIALIZATION"
	TechPHPDeserial    Technique = "PHP_DESERIALIZATION"
	TechPythonDeserial Technique = "PYTHON_DESERIALIZATION"
	TechNodeDeserial   Technique = "NODE_DESERIALIZATION"
	TechDotNetDeserial Technique = "DOTNET_DESERIALIZATION"
	TechRubyDeserial   Technique = "RUBY_DESERIALIZATION"

	// Prototype Pollution techniques
	TechProtoOverwrite  Technique = "PROTO_OVERWRITE"
	TechConstructorPoll Technique = "CONSTRUCTOR_POLLUTION"

	// GraphQL techniques
	TechIntrospection   Technique = "INTROSPECTION"
	TechBatchQuery      Technique = "BATCH_QUERY"
	TechDepthAttack     Technique = "DEPTH_ATTACK"
	TechFieldSuggestion Technique = "FIELD_SUGGESTION"
	TechDirectiveAbuse  Technique = "DIRECTIVE_ABUSE"

	// CORS techniques
	TechOriginReflect   Technique = "ORIGIN_REFLECT"
	TechNullOrigin      Technique = "NULL_ORIGIN"
	TechWildcardOrigin  Technique = "WILDCARD_ORIGIN"
	TechSubdomainOrigin Technique = "SUBDOMAIN_ORIGIN"

	// JWT techniques
	TechAlgNone      Technique = "ALG_NONE"
	TechAlgConfusion Technique = "ALG_CONFUSION"
	TechJWKInjection Technique = "JWK_INJECTION"
	TechKIDInjection Technique = "KID_INJECTION"
	TechExpTampering Technique = "EXP_TAMPERING"

	// File Upload techniques
	TechExtBypass   Technique = "EXT_BYPASS"
	TechMIMEBypass  Technique = "MIME_BYPASS"
	TechMagicBytes  Technique = "MAGIC_BYTES"
	TechDoubleExt   Technique = "DOUBLE_EXT"
	TechNullByteExt Technique = "NULL_BYTE_EXT"

	// Race Condition techniques
	TechTOCTOU       Technique = "TOCTOU"
	TechLastByteSync Technique = "LAST_BYTE_SYNC"
)

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Backward-Compatible Aliases
// The old-style payload files (ssrf.go, ssti.go, xxe.go, path_traversal.go,
// header_redirect_ldap.go) and the fuzzer engine reference these aliases.
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// PayloadCategory aliases
const (
	PayloadSQLi             = CatSQLi
	PayloadXSS              = CatXSS
	PayloadSSRF             = CatSSRF
	PayloadXXE              = CatXXE
	PayloadCommandInjection = CatCMDi
	PayloadPathTraversal    = CatPathTraversal
	PayloadSSTI             = CatSSTI
	PayloadCRLF             = CatCRLF
	PayloadHeaderInjection  = CatHeaderInjection
	PayloadHostHeader       = CatHostHeader
	PayloadOpenRedirect     = CatOpenRedirect
	PayloadLDAPi            = CatLDAPi
	PayloadNoSQLi           = CatNoSQLi
	PayloadCSRF             = CatCSRF
	PayloadIDOR             = CatIDOR
	PayloadInsecureDeserial = CatInsecureDeserial
	PayloadPrototypePollut  = CatPrototypePollut
	PayloadGraphQL          = CatGraphQL
	PayloadWebSocket        = CatWebSocket
	PayloadCORS             = CatCORS
	PayloadJWT              = CatJWT
	PayloadAuthBypass       = CatAuthBypass
	PayloadFileUpload       = CatFileUpload
	PayloadFileInclusion    = CatFileInclusion
	PayloadRaceCondition    = CatRaceCondition
)

// InjectionContext aliases
const (
	ContextURLQuery   = CtxURLQuery
	ContextURLPath    = CtxURLPath
	ContextFormBody   = CtxFormBody
	ContextJSONBody   = CtxJSONBody
	ContextXMLBody    = CtxXMLBody
	ContextHTTPHeader = CtxHTTPHeader
	ContextCookie     = CtxCookie
	ContextFragment   = CtxFragment
	ContextMultipart  = CtxMultipart
	ContextWebSocket  = CtxWebSocket
	ContextGraphQL    = CtxGraphQL
)

// Payload defines an individual test vector
type Payload struct {
	ID              string             `json:"id"               yaml:"id"`
	Category        PayloadCategory    `json:"category"         yaml:"category"`
	Technique       Technique          `json:"technique"        yaml:"technique"`
	Name            string             `json:"name"             yaml:"name"`
	Description     string             `json:"description"      yaml:"description"`
	Value           string             `json:"value"            yaml:"value"`
	Encoded         string             `json:"encoded,omitempty" yaml:"encoded,omitempty"`
	DoubleEncoded   string             `json:"double_encoded,omitempty" yaml:"double_encoded,omitempty"`
	Contexts        []InjectionContext `json:"contexts"         yaml:"contexts"`
	Detection       DetectionMethod    `json:"detection"        yaml:"detection"`
	DetectSignature string             `json:"detect_signature,omitempty" yaml:"detect_signature,omitempty"`
	DelayMs         int                `json:"delay_ms,omitempty" yaml:"delay_ms,omitempty"`
	Severity        SeverityLevel      `json:"severity"         yaml:"severity"`
	SafeMode        bool               `json:"safe_mode"        yaml:"safe_mode"`
	RiskLevel       string             `json:"risk_level,omitempty" yaml:"risk_level,omitempty"`
	TargetStack     []string           `json:"target_stack,omitempty" yaml:"target_stack,omitempty"`
	CWE             string             `json:"cwe"              yaml:"cwe"`
	OWASPCategory   string             `json:"owasp_category"   yaml:"owasp_category"`
	CVSSScore       float64            `json:"cvss_score"       yaml:"cvss_score"`
	Reference       string             `json:"reference,omitempty" yaml:"reference,omitempty"`
	Tags            []string           `json:"tags,omitempty"   yaml:"tags,omitempty"`
	Enabled         bool               `json:"enabled"          yaml:"enabled"`
}

// PayloadSet groups payloads by category for the engine to iterate
type PayloadSet struct {
	Category    PayloadCategory `json:"category"    yaml:"category"`
	Description string          `json:"description" yaml:"description"`
	Version     string          `json:"version"     yaml:"version"`
	Source      string          `json:"source"      yaml:"source"`
	Payloads    []Payload       `json:"payloads"    yaml:"payloads"`
}

// PayloadProfile defines scan intensity levels that control which payloads run
type PayloadProfile string

const (
	ProfilePassive    PayloadProfile = "PASSIVE"    // Safe probes only, no active injection
	ProfileLight      PayloadProfile = "LIGHT"      // Error-based + basic reflection only
	ProfileStandard   PayloadProfile = "STANDARD"   // All safe payloads
	ProfileAggressive PayloadProfile = "AGGRESSIVE" // Safe + time-based + moderate risk
	ProfileFull       PayloadProfile = "FULL"       // Everything including active exploitation
)

// ProfileConfig defines which payload properties are allowed per profile
type ProfileConfig struct {
	Profile             PayloadProfile    `json:"profile"`
	AllowedSeverity     []SeverityLevel   `json:"allowed_severity"`
	AllowActive         bool              `json:"allow_active"`
	AllowTimeBased      bool              `json:"allow_time_based"`
	AllowOOB            bool              `json:"allow_oob"`
	MaxPayloadsPerParam int               `json:"max_payloads_per_param"`
	Categories          []PayloadCategory `json:"categories,omitempty"` // Empty = all
	ExcludeTags         []string          `json:"exclude_tags,omitempty"`
	Description         string            `json:"description"`
}

// DefaultProfiles returns the built-in scan intensity profiles
func DefaultProfiles() map[PayloadProfile]ProfileConfig {
	return map[PayloadProfile]ProfileConfig{
		ProfilePassive: {
			Profile:         ProfilePassive,
			AllowedSeverity: []SeverityLevel{SevInfo, SevLow, SevMedium},
			AllowActive:     false, AllowTimeBased: false, AllowOOB: false,
			MaxPayloadsPerParam: 10,
			Description:         "Passive reconnaissance only â€” no active injection payloads",
		},
		ProfileLight: {
			Profile:         ProfileLight,
			AllowedSeverity: []SeverityLevel{SevInfo, SevLow, SevMedium, SevHigh},
			AllowActive:     false, AllowTimeBased: false, AllowOOB: false,
			MaxPayloadsPerParam: 25,
			Description:         "Error-based detection + basic reflection probes",
		},
		ProfileStandard: {
			Profile:         ProfileStandard,
			AllowedSeverity: []SeverityLevel{SevInfo, SevLow, SevMedium, SevHigh, SevCritical},
			AllowActive:     false, AllowTimeBased: false, AllowOOB: true,
			MaxPayloadsPerParam: 50,
			Description:         "Full safe payload coverage with OOB callbacks",
		},
		ProfileAggressive: {
			Profile:         ProfileAggressive,
			AllowedSeverity: []SeverityLevel{SevInfo, SevLow, SevMedium, SevHigh, SevCritical},
			AllowActive:     true, AllowTimeBased: true, AllowOOB: true,
			MaxPayloadsPerParam: 100,
			Description:         "Active fuzzing with time-based and moderate risk payloads",
		},
		ProfileFull: {
			Profile:         ProfileFull,
			AllowedSeverity: []SeverityLevel{SevInfo, SevLow, SevMedium, SevHigh, SevCritical},
			AllowActive:     true, AllowTimeBased: true, AllowOOB: true,
			MaxPayloadsPerParam: 0, // Unlimited
			Description:         "Complete payload library â€” authorized penetration testing only",
		},
	}
}
