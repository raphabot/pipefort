package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// decodeSARIF runs ReportSARIF and parses the result back into a generic map so
// tests can assert on the SARIF 2.1.0 shape without importing a schema lib.
func decodeSARIF(t *testing.T, findings []scanner.Finding) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := ReportSARIF(&buf, findings); err != nil {
		t.Fatalf("ReportSARIF returned error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("ReportSARIF produced invalid JSON: %v\n%s", err, buf.String())
	}
	return out
}

func TestReportSARIF_TopLevelShape(t *testing.T) {
	out := decodeSARIF(t, nil)

	if out["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", out["version"])
	}
	if _, ok := out["$schema"]; !ok {
		t.Error("missing $schema")
	}
	runs, ok := out["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %v", out["runs"])
	}

	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "Pipefort" {
		t.Errorf("driver.name = %v, want Pipefort", driver["name"])
	}

	// The driver must advertise the full catalog plus the synthetic system rule,
	// so every result ruleId resolves to a declared rule.
	rules := driver["rules"].([]any)
	wantRules := len(scanner.Rules()) + 1
	if len(rules) != wantRules {
		t.Errorf("driver.rules count = %d, want %d", len(rules), wantRules)
	}

	// Even with no findings, results must be an array (never null) for consumers.
	if run["results"] == nil {
		t.Error("results should be an empty array, not null")
	}
}

func TestReportSARIF_SeverityLevelMapping(t *testing.T) {
	findings := []scanner.Finding{
		{File: "a.yml", Line: 5, Column: 3, Severity: scanner.SeverityHigh, RuleID: scanner.RulePPEShellInjection, Category: "CICD-SEC-4", Title: "t", Description: "d", Recommendation: "r"},
		{File: "a.yml", Line: 7, Column: 1, Severity: scanner.SeverityMedium, RuleID: scanner.RuleUnpinnedAction, Category: "CICD-SEC-3", Title: "t", Description: "d", Recommendation: "r"},
		{File: "a.yml", Line: 9, Column: 1, Severity: scanner.SeverityLow, RuleID: scanner.RuleMissingTimeout, Category: "BEST-PRAC-2", Title: "t", Description: "d", Recommendation: "r"},
	}
	out := decodeSARIF(t, findings)
	results := out["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("results count = %d, want 3", len(results))
	}

	wantLevels := []string{"error", "warning", "note"}
	for i, r := range results {
		res := r.(map[string]any)
		if res["level"] != wantLevels[i] {
			t.Errorf("result[%d].level = %v, want %v", i, res["level"], wantLevels[i])
		}
		loc := res["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
		if loc["artifactLocation"].(map[string]any)["uri"] != "a.yml" {
			t.Errorf("result[%d] uri = %v, want a.yml", i, loc["artifactLocation"])
		}
		region := loc["region"].(map[string]any)
		if int(region["startLine"].(float64)) != findings[i].Line {
			t.Errorf("result[%d].startLine = %v, want %d", i, region["startLine"], findings[i].Line)
		}
	}
}

func TestReportSARIF_SettingsFindingHasNoRegion(t *testing.T) {
	// Repository-settings findings have Line 0 and the synthetic file label;
	// SARIF regions are 1-based, so no region must be emitted for them.
	findings := []scanner.Finding{
		{File: scanner.SettingsFile, Line: 0, Severity: scanner.SeverityHigh, RuleID: scanner.RuleBPMissing, Category: "CICD-SEC-1", Title: "t", Description: "d", Recommendation: "r"},
	}
	out := decodeSARIF(t, findings)
	res := out["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	loc := res["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if _, hasRegion := loc["region"]; hasRegion {
		t.Error("settings finding (Line 0) should not carry a region")
	}
}

func TestReportSARIF_SystemFindingUsesSyntheticRule(t *testing.T) {
	// A finding with an empty RuleID (SYSTEM notice) must map to the synthetic
	// rule id rather than emit a dangling/empty ruleId.
	findings := []scanner.Finding{
		{File: "bad.yml", Line: 1, Severity: scanner.SeverityInfo, RuleID: "", Title: "parse error", Description: "d", Recommendation: "r"},
	}
	out := decodeSARIF(t, findings)
	res := out["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	if res["ruleId"] != systemRuleID {
		t.Errorf("system finding ruleId = %v, want %s", res["ruleId"], systemRuleID)
	}
}

func TestReportSARIF_HelpURIPointsAtDocs(t *testing.T) {
	out := decodeSARIF(t, nil)
	rules := out["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	for _, r := range rules {
		rule := r.(map[string]any)
		if rule["id"] == systemRuleID {
			continue
		}
		help, _ := rule["helpUri"].(string)
		if !strings.HasPrefix(help, docsBaseURL+"/rules/") {
			t.Errorf("rule %v helpUri = %q, want prefix %s/rules/", rule["id"], help, docsBaseURL)
		}
	}
}

func TestReportSARIF_PartialFingerprints(t *testing.T) {
	out := decodeSARIF(t, []scanner.Finding{
		{
			File: ".github/workflows/ci.yml", Line: 5, Severity: scanner.SeverityHigh,
			Category: "CICD-SEC-4", RuleID: scanner.RulePPEShellInjection,
			Title: "T", Description: "D",
		},
	})
	run := out["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	pf, ok := result["partialFingerprints"].(map[string]any)
	if !ok {
		t.Fatalf("missing partialFingerprints: %v", result)
	}
	fp, _ := pf["pipefort/v1"].(string)
	if len(fp) < 32 {
		t.Fatalf("pipefort/v1 fingerprint = %q, want a hash", fp)
	}

	// Stable across line shifts: same finding on a different line hashes the same.
	out2 := decodeSARIF(t, []scanner.Finding{
		{
			File: ".github/workflows/ci.yml", Line: 99, Severity: scanner.SeverityHigh,
			Category: "CICD-SEC-4", RuleID: scanner.RulePPEShellInjection,
			Title: "T", Description: "D",
		},
	})
	run2 := out2["runs"].([]any)[0].(map[string]any)
	pf2 := run2["results"].([]any)[0].(map[string]any)["partialFingerprints"].(map[string]any)
	if pf2["pipefort/v1"] != fp {
		t.Fatalf("fingerprint changed with line shift: %v vs %v", pf2["pipefort/v1"], fp)
	}
}
