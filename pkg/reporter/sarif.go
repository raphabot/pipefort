package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// SARIF 2.1.0 output. Emitting SARIF lets Pipefort findings flow into GitHub
// Advanced Security (the Security tab + inline PR annotations) via
// github/codeql-action/upload-sarif, matching what zizmor/poutine/scorecard do.
//
// Only the flat findings list is exported — toxic combinations ("Attacker Mind")
// have no natural SARIF analog, so they stay in the console/JSON reports.

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	// docsBaseURL prefixes RuleSpec.DocURL ("/rules/<id>") to form a helpUri.
	docsBaseURL = "https://pipefort.com/docs"
	// systemRuleID is the synthetic ruleId for findings without a real RuleID
	// (parse errors / settings-audit failures emitted as SYSTEM INFO notices).
	systemRuleID = "pipefort-system"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints lets GitHub code scanning track a result across
	// commits instead of closing + reopening it when lines shift. Uses the
	// same stable identity as the web app's cross-scan diffing.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

// severityToLevel maps Pipefort severities to SARIF result levels.
// HIGH→error, MEDIUM→warning, LOW/INFO→note.
func severityToLevel(s scanner.Severity) string {
	switch s {
	case scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity gives GitHub code scanning a 0-10 score to sort/filter on.
func securitySeverity(s scanner.Severity) string {
	switch s {
	case scanner.SeverityHigh:
		return "8.0"
	case scanner.SeverityMedium:
		return "5.0"
	case scanner.SeverityLow:
		return "2.0"
	default:
		return "0.0"
	}
}

// ReportSARIF writes findings as a SARIF 2.1.0 log. The driver advertises the
// full Pipefort rule catalog (so every result's ruleId resolves to a rule with
// a helpUri), and each finding becomes one result.
func ReportSARIF(w io.Writer, findings []scanner.Finding) error {
	rules := make([]sarifRule, 0, len(scanner.Rules())+1)
	for _, r := range scanner.Rules() {
		rules = append(rules, sarifRule{
			ID:                   string(r.ID),
			Name:                 r.Title,
			ShortDescription:     sarifText{Text: r.Title},
			FullDescription:      sarifText{Text: r.Description},
			HelpURI:              docsBaseURL + r.DocURL,
			DefaultConfiguration: sarifConfig{Level: severityToLevel(r.DefaultSeverity)},
			Properties: map[string]any{
				"category":          r.Category,
				"security-severity": securitySeverity(r.DefaultSeverity),
				"tags":              append([]string{r.Category}, r.Frameworks...),
				"confidence":        string(r.DefaultConfidence),
				"persona":           string(r.Persona),
			},
		})
	}
	// Synthetic rule so SYSTEM findings (empty RuleID) still reference a
	// declared rule rather than a dangling ruleId.
	rules = append(rules, sarifRule{
		ID:                   systemRuleID,
		Name:                 "Pipefort system notice",
		ShortDescription:     sarifText{Text: "Pipefort system notice"},
		FullDescription:      sarifText{Text: "A non-rule notice emitted by Pipefort (e.g. a YAML parse error or a settings-audit failure)."},
		DefaultConfiguration: sarifConfig{Level: "note"},
	})

	// Ensure every result carries the stable cross-scan identity. Callers may
	// have assigned fingerprints already; assigning twice is idempotent.
	scanner.AssignFingerprints(findings)

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		ruleID := string(f.RuleID)
		if ruleID == "" {
			ruleID = systemRuleID
		}

		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: f.File},
			},
		}
		// Repository-settings findings carry Line 0 and a synthetic file label;
		// SARIF regions are 1-based, so only attach a region for real source
		// locations.
		if f.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{
				StartLine:   f.Line,
				StartColumn: f.Column,
			}
		}

		props := map[string]any{
			"category":          f.Category,
			"security-severity": securitySeverity(f.Severity),
		}
		if f.Confidence != "" {
			props["confidence"] = string(f.Confidence)
		}
		results = append(results, sarifResult{
			RuleID:    ruleID,
			Level:     severityToLevel(f.Severity),
			Message:   sarifText{Text: fmt.Sprintf("%s %s", f.Description, f.Recommendation)},
			Locations: []sarifLocation{loc},
			PartialFingerprints: map[string]string{
				"pipefort/v1": f.Fingerprint,
			},
			Properties: props,
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "Pipefort", InformationURI: "https://pipefort.com", Rules: rules}},
			Results: results,
		}},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}
