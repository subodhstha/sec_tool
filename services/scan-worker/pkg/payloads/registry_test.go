package payloads

import (
	"testing"
)

func TestRegistryLoadBuiltins(t *testing.T) {
	r := NewRegistry()

	total := r.TotalPayloads()
	if total == 0 {
		t.Fatal("Registry loaded with 0 payloads â€” expected > 100")
	}
	t.Logf("Registry loaded %d total payloads", total)

	// Verify minimum payloads per critical category
	expectedMinimums := map[PayloadCategory]int{
		// Core families
		PayloadSQLi:             25,
		PayloadXSS:              15,
		PayloadSSRF:             10,
		PayloadCommandInjection: 10,
		PayloadXXE:              5,
		PayloadPathTraversal:    10,
		PayloadSSTI:             10,
		PayloadCRLF:             4,
		PayloadOpenRedirect:     5,
		PayloadLDAPi:            3,
		// Extended families
		PayloadNoSQLi:           5,
		PayloadCORS:             5,
		PayloadCSRF:             5,
		PayloadGraphQL:          5,
		PayloadJWT:              5,
		PayloadInsecureDeserial: 10,
		PayloadPrototypePollut:  3,
		PayloadIDOR:             3,
		PayloadAuthBypass:       3,
		PayloadFileUpload:       5,
		PayloadFileInclusion:    5,
		PayloadWebSocket:        3,
		PayloadRaceCondition:    3,
	}

	stats := r.Stats()
	for cat, minCount := range expectedMinimums {
		actual, ok := stats[cat]
		if !ok {
			t.Errorf("Category %s not found in registry", cat)
			continue
		}
		if actual < minCount {
			t.Errorf("Category %s: expected >= %d payloads, got %d", cat, minCount, actual)
		}
	}

	t.Log(r.Summary())
}

func TestRegistryGetByCategory(t *testing.T) {
	r := NewRegistry()

	sqli := r.GetByCategory(PayloadSQLi)
	if len(sqli) == 0 {
		t.Fatal("No SQLi payloads returned")
	}

	// Verify all returned payloads have correct category
	for _, p := range sqli {
		if p.Category != PayloadSQLi && p.Category != PayloadNoSQLi {
			t.Errorf("Payload %s has unexpected category %s in SQLi set", p.ID, p.Category)
		}
	}
}

func TestRegistryGetByContext(t *testing.T) {
	r := NewRegistry()

	urlQueryPayloads := r.GetByContext(ContextURLQuery)
	if len(urlQueryPayloads) == 0 {
		t.Fatal("No payloads for URL_QUERY context")
	}

	// Verify all returned payloads include the requested context
	for _, p := range urlQueryPayloads {
		found := false
		for _, c := range p.Contexts {
			if c == ContextURLQuery {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Payload %s returned for URL_QUERY context but doesn't include it", p.ID)
		}
	}

	xmlPayloads := r.GetByContext(ContextXMLBody)
	if len(xmlPayloads) == 0 {
		t.Fatal("No payloads for XML_BODY context â€” expected XXE payloads")
	}
}

func TestRegistryGetSafePayloads(t *testing.T) {
	r := NewRegistry()

	safe := r.GetSafePayloads()
	if len(safe) == 0 {
		t.Fatal("No safe payloads returned")
	}

	for _, p := range safe {
		if !p.SafeMode {
			t.Errorf("Payload %s returned as safe but SafeMode=false", p.ID)
		}
	}

	active := r.GetActivePayloads()
	if len(active) == 0 {
		t.Fatal("No active payloads returned â€” expected time-based and RCE payloads")
	}

	for _, p := range active {
		if p.SafeMode {
			t.Errorf("Payload %s returned as active but SafeMode=true", p.ID)
		}
	}

	t.Logf("Safe payloads: %d, Active payloads: %d", len(safe), len(active))
}

func TestRegistryFilterPayloads(t *testing.T) {
	r := NewRegistry()

	// Filter: SQLi + URL_QUERY + Safe only
	results := r.FilterPayloads(FilterOptions{
		Categories: []PayloadCategory{PayloadSQLi},
		Contexts:   []InjectionContext{ContextURLQuery},
		SafeOnly:   true,
	})
	if len(results) == 0 {
		t.Fatal("No results for SQLi + URL_QUERY + safe filter")
	}
	for _, p := range results {
		if p.Category != PayloadSQLi && p.Category != PayloadNoSQLi {
			t.Errorf("Filter leak: payload %s category %s", p.ID, p.Category)
		}
		if !p.SafeMode {
			t.Errorf("Filter leak: payload %s is not safe", p.ID)
		}
	}

	// Filter: MySQL stack targeting
	mysqlResults := r.FilterPayloads(FilterOptions{
		Categories:  []PayloadCategory{PayloadSQLi},
		TargetStack: []string{"MySQL"},
	})
	for _, p := range mysqlResults {
		if len(p.TargetStack) > 0 {
			found := false
			for _, ts := range p.TargetStack {
				if ts == "MySQL" {
					found = true
				}
			}
			if !found {
				t.Errorf("Payload %s doesn't target MySQL but was returned", p.ID)
			}
		}
	}

	// Filter: Time-based detection only
	timeResults := r.FilterPayloads(FilterOptions{
		Detection: []DetectionMethod{DetectTimeDelta},
	})
	if len(timeResults) == 0 {
		t.Fatal("No time-based payloads found")
	}
	for _, p := range timeResults {
		if p.Detection != DetectTimeDelta {
			t.Errorf("Payload %s has detection %s, expected TIME_DELTA", p.ID, p.Detection)
		}
		if p.DelayMs <= 0 {
			t.Errorf("Time-based payload %s has no DelayMs", p.ID)
		}
	}
}

func TestRegistryCustomPayloadSet(t *testing.T) {
	r := NewRegistry()
	originalTotal := r.TotalPayloads()

	custom := PayloadSet{
		Category:    PayloadSQLi,
		Description: "Custom enterprise payloads",
		Payloads: []Payload{
			{
				ID: "custom-sqli-1", Category: PayloadSQLi,
				Name: "Custom Test", Value: "' OR custom=1-- -",
				Contexts:  []InjectionContext{ContextURLQuery},
				Detection: DetectContentDiff,
				RiskLevel: "SAFE", SafeMode: true,
				CWE: "CWE-89", OWASPCategory: "A03:2021",
			},
		},
	}

	r.RegisterCustomSet(custom)
	newTotal := r.TotalPayloads()

	if newTotal != originalTotal+1 {
		t.Errorf("Expected %d payloads after custom add, got %d", originalTotal+1, newTotal)
	}

	// Verify the custom payload is findable
	sqli := r.GetByCategory(PayloadSQLi)
	found := false
	for _, p := range sqli {
		if p.ID == "custom-sqli-1" {
			found = true
		}
	}
	if !found {
		t.Error("Custom payload not found in SQLi category after registration")
	}

	r.RegisterCustomSet(custom)
	if r.TotalPayloads() != newTotal {
		t.Errorf("Duplicate custom registration changed total from %d to %d", newTotal, r.TotalPayloads())
	}
}

func TestPayloadStructureIntegrity(t *testing.T) {
	r := NewRegistry()

	for _, p := range r.GetSafePayloads() {
		if p.ID == "" {
			t.Error("Payload with empty ID found")
		}
		if p.Value == "" {
			t.Errorf("Payload %s has empty Value", p.ID)
		}
		if p.CWE == "" {
			t.Errorf("Payload %s missing CWE", p.ID)
		}
		if p.OWASPCategory == "" {
			t.Errorf("Payload %s missing OWASP category", p.ID)
		}
		if len(p.Contexts) == 0 {
			t.Errorf("Payload %s has no injection contexts", p.ID)
		}
		if p.Detection == "" {
			t.Errorf("Payload %s has no detection method", p.ID)
		}
	}
}

func TestPayloadIDUniqueness(t *testing.T) {
	r := NewRegistry()

	seen := make(map[string]bool)
	allPayloads := r.FilterPayloads(FilterOptions{})

	for _, p := range allPayloads {
		if seen[p.ID] {
			t.Errorf("Duplicate payload ID: %s", p.ID)
		}
		seen[p.ID] = true
	}

	t.Logf("Verified %d unique payload IDs", len(seen))
}

func TestOWASPCoverage(t *testing.T) {
	r := NewRegistry()
	allPayloads := r.FilterPayloads(FilterOptions{})

	owaspCoverage := make(map[string]int)
	for _, p := range allPayloads {
		owaspCoverage[p.OWASPCategory]++
	}

	// Verify we cover the critical OWASP Top 10 2021 categories
	criticalCategories := []string{
		"A01:2021", // Broken Access Control
		"A03:2021", // Injection
		"A05:2021", // Security Misconfiguration
		"A10:2021", // SSRF
	}

	for _, cat := range criticalCategories {
		if count, ok := owaspCoverage[cat]; !ok || count == 0 {
			t.Errorf("OWASP category %s has no coverage", cat)
		} else {
			t.Logf("OWASP %s: %d payloads", cat, count)
		}
	}
}
