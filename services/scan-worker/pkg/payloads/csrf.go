package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// CSRF Payloads â€” Sourced from PayloadsAllTheThings/CSRF Injection
// Covers: Missing Token, SameSite Bypass, Method Override, Content-Type Bypass,
//         Referer/Origin Bypass, Flash-based CSRF
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func CSRFPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatCSRF,
		Description: "Cross-Site Request Forgery â€” PayloadsAllTheThings + CWE-352",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection",
		Payloads:    csrfAll(),
	}
}

func csrfAll() []Payload {
	return []Payload{
		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Token Missing / Validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "csrf-no-token", Category: CatCSRF,
			Technique: TechTokenMissing,
			Name: "Missing CSRF Token", Value: `VYOMITE_STRIP_PARAM:csrf_token`,
			Contexts:  []InjectionContext{CtxFormBody, CtxJSONBody},
			Detection: DetectStatusCode,
			Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "Remove CSRF token from request â€” test if server validates its presence",
			Reference: "PayloadsAllTheThings", Tags: []string{"token_missing"}, Enabled: true,
		},
		{
			ID: "csrf-empty-token", Category: CatCSRF,
			Technique: TechTokenMissing,
			Name: "Empty CSRF Token", Value: `csrf_token=`,
			Contexts:  []InjectionContext{CtxFormBody},
			Detection: DetectStatusCode,
			Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "Empty string as CSRF token â€” tests for presence-only validation",
			Reference: "PayloadsAllTheThings", Tags: []string{"token_empty"}, Enabled: true,
		},
		{
			ID: "csrf-modified-token", Category: CatCSRF,
			Technique: TechTokenMissing,
			Name: "Modified CSRF Token", Value: `csrf_token=vyomite_invalid_token_12345`,
			Contexts:  []InjectionContext{CtxFormBody},
			Detection: DetectStatusCode,
			Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "Random invalid token â€” tests if token is actually validated",
			Reference: "PayloadsAllTheThings", Tags: []string{"token_validation"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Method Override â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "csrf-method-override-header", Category: CatCSRF,
			Technique: TechMethodOverride,
			Name: "X-HTTP-Method-Override", Value: `GET`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectStatusCode,
			Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "X-HTTP-Method-Override header to convert POST to GET â€” bypasses CSRF on GET",
			Reference: "PayloadsAllTheThings", Tags: []string{"method_override"}, Enabled: true,
		},
		{
			ID: "csrf-method-get-fallback", Category: CatCSRF,
			Technique: TechMethodOverride,
			Name: "GET Method Fallback", Value: `_method=GET`,
			Contexts:  []InjectionContext{CtxFormBody, CtxURLQuery},
			Detection: DetectStatusCode,
			Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "Rails/Laravel _method param to override HTTP method",
			Reference: "PayloadsAllTheThings", Tags: []string{"method_override"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Content-Type Bypass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "csrf-ct-urlencoded", Category: CatCSRF,
			Technique: TechContentType,
			Name: "Content-Type: URL-Encoded", Value: `application/x-www-form-urlencoded`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectStatusCode,
			Severity: SevMedium, SafeMode: true, CVSSScore: 6.5,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "Switch JSON endpoint to form-urlencoded â€” bypasses pre-flight CORS",
			Reference: "PayloadsAllTheThings", Tags: []string{"content_type"}, Enabled: true,
		},
		{
			ID: "csrf-ct-text-plain", Category: CatCSRF,
			Technique: TechContentType,
			Name: "Content-Type: text/plain", Value: `text/plain`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectStatusCode,
			Severity: SevMedium, SafeMode: true, CVSSScore: 6.5,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "text/plain Content-Type to avoid CORS pre-flight for cross-origin forms",
			Reference: "PayloadsAllTheThings", Tags: []string{"content_type"}, Enabled: true,
		},
		{
			ID: "csrf-ct-multipart", Category: CatCSRF,
			Technique: TechContentType,
			Name: "Content-Type: multipart/form-data", Value: `multipart/form-data`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectStatusCode,
			Severity: SevMedium, SafeMode: true, CVSSScore: 6.5,
			CWE: "CWE-352", OWASPCategory: "A01:2021",
			Description: "multipart/form-data to bypass JSON-only endpoint CSRF protection",
			Reference: "PayloadsAllTheThings", Tags: []string{"content_type"}, Enabled: true,
		},
	}
}
