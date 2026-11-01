package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// CORS Misconfiguration Payloads â€” Sourced from PayloadsAllTheThings/CORS Misconfiguration
// Covers: Origin Reflection, Null Origin, Subdomain Bypass, Wildcard,
//         Pre-flight Bypass, Credential Leak Detection
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func CORSPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatCORS,
		Description: "CORS Misconfiguration â€” PayloadsAllTheThings + CWE-942",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration",
		Payloads:    corsAll(),
	}
}

func corsAll() []Payload {
	return []Payload{
		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Origin Reflection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "cors-origin-reflect", Category: CatCORS,
			Technique: TechOriginReflect,
			Name: "Origin Header Reflection", Value: `https://evil.vyomite.example.com`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Origin:\s*https://evil\.vyomite\.example\.com`,
			Severity: SevHigh, SafeMode: true, CVSSScore: 8.1,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Origin header reflected in ACAO â€” allows cross-origin data theft",
			Reference: "PayloadsAllTheThings", Tags: []string{"origin_reflect"}, Enabled: true,
		},
		{
			ID: "cors-origin-reflect-creds", Category: CatCORS,
			Technique: TechOriginReflect,
			Name: "Origin Reflect + Credentials", Value: `https://evil.vyomite.example.com`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Credentials:\s*true`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.1,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Origin reflected with Allow-Credentials: true â€” full credential theft possible",
			Reference: "PayloadsAllTheThings", Tags: []string{"origin_reflect", "credentials"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Null Origin â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "cors-null-origin", Category: CatCORS,
			Technique: TechNullOrigin,
			Name: "Null Origin Bypass", Value: `null`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Origin:\s*null`,
			Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Null origin accepted â€” sandboxed iframes and data: URIs send null origin",
			Reference: "PayloadsAllTheThings", Tags: []string{"null_origin"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Subdomain Bypass â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "cors-subdomain-prefix", Category: CatCORS,
			Technique: TechSubdomainOrigin,
			Name: "Subdomain Prefix Bypass", Value: `https://target.com.evil.vyomite.example.com`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Origin:`,
			Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Subdomain prefix bypass â€” regex anchor missing on origin check",
			Reference: "PayloadsAllTheThings", Tags: []string{"subdomain_bypass"}, Enabled: true,
		},
		{
			ID: "cors-subdomain-suffix", Category: CatCORS,
			Technique: TechSubdomainOrigin,
			Name: "Subdomain Suffix Bypass", Value: `https://evil-target.com`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Origin:`,
			Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Domain suffix bypass â€” endsWith check without dot boundary",
			Reference: "PayloadsAllTheThings", Tags: []string{"subdomain_bypass"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Wildcard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "cors-wildcard-star", Category: CatCORS,
			Technique: TechWildcardOrigin,
			Name: "Wildcard * Origin Detection", Value: `https://any-random-origin.example.com`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Origin:\s*\*`,
			Severity: SevMedium, SafeMode: true, CVSSScore: 5.4,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Wildcard ACAO header â€” sensitive if combined with authenticated endpoints",
			Reference: "PayloadsAllTheThings", Tags: []string{"wildcard"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Special Chars in Origin â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "cors-underscore-origin", Category: CatCORS,
			Technique: TechOriginReflect,
			Name: "Underscore Domain Bypass", Value: `https://target.com_.evil.vyomite.example.com`,
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Origin:`,
			Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Underscore in subdomain â€” may bypass regex-based origin validation",
			Reference: "PayloadsAllTheThings", Tags: []string{"special_chars"}, Enabled: true,
		},
		{
			ID: "cors-backtick-origin", Category: CatCORS,
			Technique: TechOriginReflect,
			Name: "Backtick Origin Bypass", Value: "https://target.com`.evil.vyomite.example.com",
			Contexts:  []InjectionContext{CtxHTTPHeader},
			Detection: DetectHeaderInject, DetectSignature: `Access-Control-Allow-Origin:`,
			Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
			CWE: "CWE-942", OWASPCategory: "A05:2021",
			Description: "Backtick char in origin â€” Safari/Edge may interpret differently",
			Reference: "PayloadsAllTheThings", Tags: []string{"special_chars", "browser_specific"}, Enabled: true,
		},
	}
}
