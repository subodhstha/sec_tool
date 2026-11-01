package models

import (
	"fmt"
	"strings"
)

// SARIFReport represents the root OASIS SARIF v2.1.0 JSON format
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool      SARIFTool     `json:"tool"`
	Results   []SARIFResult `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ShortDescription SARIFMessage         `json:"shortDescription"`
	FullDescription  SARIFMessage         `json:"fullDescription"`
	HelpURI          string               `json:"helpUri,omitempty"`
	Properties       SARIFRuleProperties  `json:"properties"`
}

type SARIFRuleProperties struct {
	SecuritySeverity string   `json:"security-severity"`
	Tags             []string `json:"tags"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"` // "error", "warning", "note", "none"
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type SARIFInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// MapSeverityToSARIFLevel converts internal severity to SARIF result levels
func MapSeverityToSARIFLevel(sev VulnerabilitySeverity) string {
	switch sev {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow, SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// MapCVSSScore converts score to SARIF security-severity string (0.0 - 10.0)
func MapCVSSScore(score float64) string {
	return fmt.Sprintf("%.1f", score)
}

// GenerateSARIFReport converts a slice of VulnerabilityFinding into a SARIF 2.1.0 document (FR-5.2)
func GenerateSARIFReport(scanID, targetURL string, findings []VulnerabilityFinding) *SARIFReport {
	ruleMap := make(map[string]SARIFRule)
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		ruleID := string(f.Category)
		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = SARIFRule{
				ID:   ruleID,
				Name: f.Title,
				ShortDescription: SARIFMessage{
					Text: f.Title,
				},
				FullDescription: SARIFMessage{
					Text: f.Description,
				},
				HelpURI: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(f.CWE, "CWE-")),
				Properties: SARIFRuleProperties{
					SecuritySeverity: MapCVSSScore(f.CVSSScore),
					Tags: func() []string {
						t := []string{"security", f.OWASPCategory, f.CWE, string(f.Severity)}
						if f.ISO27001Control != "" {
							t = append(t, "ISO27001:"+f.ISO27001Control)
						}
						if f.NISTControl != "" {
							t = append(t, "NIST:"+f.NISTControl)
						}
						if f.NSACISAGuidance != "" {
							t = append(t, "NSA-CISA:"+f.NSACISAGuidance)
						}
						return t
					}(),
				},
			}
		}

		resMessage := fmt.Sprintf("%s found at %s. Remediation: %s", f.Title, f.TargetURL, f.Remediation)
		if f.AffectedParameter != "" {
			resMessage = fmt.Sprintf("%s found in parameter '%s' (%s) at %s. Remediation: %s",
				f.Title, f.AffectedParameter, f.InjectionContext, f.TargetURL, f.Remediation)
		}

		fingerprints := map[string]string{
			"dedupHash": f.DedupHash,
		}

		result := SARIFResult{
			RuleID:  ruleID,
			Level:   MapSeverityToSARIFLevel(f.Severity),
			Message: SARIFMessage{Text: resMessage},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.TargetURL,
						},
					},
				},
			},
			PartialFingerprints: fingerprints,
		}
		results = append(results, result)
	}

	rules := make([]SARIFRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	return &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Vyomite DAST Scanner",
						Version:        "1.0.0",
						InformationURI: "https://vyomite.internal/security",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{ExecutionSuccessful: true},
				},
			},
		},
	}
}
