package scanner

import "testing"

func boolPtr(b bool) *bool { return &b }

func TestParseRepoConfigValidation(t *testing.T) {
	good := []byte(`
ruleset: owasp
min-confidence: MEDIUM
persona: pedantic
rules:
  cicd-sec-3-unpinned-action:
    severity: LOW
`)
	if _, err := ParseRepoConfig(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	for _, bad := range []string{
		"persona: auditer",
		"min-confidence: SUPER",
		"rules:\n  x:\n    severity: NOPE",
	} {
		if _, err := ParseRepoConfig([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestApplyRepoConfig(t *testing.T) {
	findings := []Finding{
		{RuleID: RuleUnpinnedAction, File: ".github/workflows/ci.yml", Line: 10, Severity: SeverityMedium},
		{RuleID: RuleMissingTimeout, File: ".github/workflows/ci.yml", Line: 20, Severity: SeverityLow},
		{RuleID: RuleHardcodedSecrets, File: ".github/workflows/release.yml", Line: 5, Severity: SeverityHigh},
		{Category: "SYSTEM", File: SettingsFile}, // always passes
	}

	cfg := &RepoConfig{Rules: map[string]RuleOverride{
		// Disable timeouts entirely.
		string(RuleMissingTimeout): {Enabled: boolPtr(false)},
		// Downgrade unpinned to LOW.
		string(RuleUnpinnedAction): {Severity: "low"},
		// Ignore the hardcoded-secret finding in the release workflow.
		string(RuleHardcodedSecrets): {Ignore: []IgnoreEntry{{File: ".github/workflows/release.yml"}}},
	}}

	out := ApplyRepoConfig(findings, cfg)
	// timeout dropped, hardcoded-secret ignored → unpinned (downgraded) + SYSTEM.
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(out), out)
	}
	var sawUnpinnedLow, sawSystem bool
	for _, f := range out {
		if f.RuleID == RuleUnpinnedAction {
			sawUnpinnedLow = f.Severity == SeverityLow
		}
		if f.Category == "SYSTEM" {
			sawSystem = true
		}
	}
	if !sawUnpinnedLow {
		t.Error("unpinned severity was not downgraded to LOW")
	}
	if !sawSystem {
		t.Error("SYSTEM finding must always pass ApplyRepoConfig")
	}
}

func TestApplyRepoConfigLineScopedIgnore(t *testing.T) {
	findings := []Finding{
		{RuleID: RuleUnpinnedAction, File: "a.yml", Line: 10},
		{RuleID: RuleUnpinnedAction, File: "a.yml", Line: 20},
	}
	cfg := &RepoConfig{Rules: map[string]RuleOverride{
		string(RuleUnpinnedAction): {Ignore: []IgnoreEntry{{File: "a.yml", Lines: []int{10}}}},
	}}
	out := ApplyRepoConfig(findings, cfg)
	if len(out) != 1 || out[0].Line != 20 {
		t.Fatalf("expected only line-20 finding to survive, got %+v", out)
	}
}

func TestMatchFileGlob(t *testing.T) {
	cases := []struct {
		pattern, file string
		want          bool
	}{
		{".github/workflows/ci.yml", ".github/workflows/ci.yml", true},
		{".github/workflows/*.yml", ".github/workflows/ci.yml", true},
		{".github/workflows/ci.yml", "/tmp/clone/.github/workflows/ci.yml", true}, // tail match
		{".github/workflows/*.yml", "/abs/.github/workflows/deploy.yml", true},
		{".github/workflows/ci.yml", ".github/workflows/other.yml", false},
	}
	for _, tc := range cases {
		if got := matchFileGlob(tc.pattern, tc.file); got != tc.want {
			t.Errorf("matchFileGlob(%q, %q) = %v, want %v", tc.pattern, tc.file, got, tc.want)
		}
	}
}

func TestDisabledRuleIDs(t *testing.T) {
	cfg := &RepoConfig{Rules: map[string]RuleOverride{
		string(RuleMissingTimeout):  {Enabled: boolPtr(false)},
		string(RuleUnpinnedAction):  {Enabled: boolPtr(true)}, // explicitly enabled → not in set
		string(RuleHardcodedSecrets): {Severity: "low"},       // no enable flag → not in set
	}}
	got := cfg.DisabledRuleIDs()
	if len(got) != 1 || !got[RuleMissingTimeout] {
		t.Fatalf("expected only missing-timeout disabled, got %v", got)
	}
}
