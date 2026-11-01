package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestGenerateSARIFReport(t *testing.T) {
	findings := []VulnerabilityFinding{
		{
			ID:                "vuln-1",
			ScanID:            "scan-100",
			Title:             "SQL Injection in Search",
			Description:       "Unescaped parameter passed to query",
			Remediation:       "Use prepared statements",
			Category:          CategorySQLi,
			Severity:          SeverityCritical,
			CVSSScore:         9.8,
			CWE:               "CWE-89",
			OWASPCategory:     "A03:2021-Injection",
			TargetURL:         "https://staging.internal/api/search",
			AffectedParameter: "q",
			InjectionContext:  "query",
			DedupHash:         ComputeDedupHash("q", "query", CategorySQLi),
			DiscoveredAt:      time.Now(),
		},
	}

	report := GenerateSARIFReport("scan-100", "https://staging.internal", findings)

	if report.Version != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %s", report.Version)
	}

	if len(report.Runs) == 0 || len(report.Runs[0].Results) != 1 {
		t.Fatalf("Expected 1 result in run, got %v", report.Runs)
	}

	res := report.Runs[0].Results[0]
	if res.Level != "error" {
		t.Errorf("Expected level 'error' for CRITICAL severity, got %s", res.Level)
	}

	// Verify valid JSON serialization
	bytes, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to serialize SARIF report to JSON: %v", err)
	}

	if len(bytes) == 0 {
		t.Errorf("Serialized SARIF JSON is empty")
	}
}
