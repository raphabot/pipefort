package scanner

import "testing"

// fnd builds a minimal finding tagged with a rule id + file for combo tests.
func fnd(rule RuleID, file string, line int) Finding {
	return Finding{File: file, Line: line, RuleID: rule, Severity: SeverityHigh, Title: string(rule)}
}

// comboByID returns the first detected combo with the given id, or false.
func comboByID(combos []ToxicCombo, id string) (ToxicCombo, bool) {
	for _, c := range combos {
		if c.ID == id {
			return c, true
		}
	}
	return ToxicCombo{}, false
}

func TestDetectToxicCombinations_Empty(t *testing.T) {
	if got := DetectToxicCombinations(nil); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
	if got := DetectToxicCombinations([]Finding{}); got != nil {
		t.Fatalf("expected nil for empty slice, got %v", got)
	}
}

func TestDetectToxicCombinations_PwnRequestSameFile(t *testing.T) {
	findings := []Finding{
		fnd(RulePPECheckout, ".github/workflows/ci.yml", 10),
		fnd(RuleMissingPermissions, ".github/workflows/ci.yml", 1),
	}
	combos := DetectToxicCombinations(findings)
	c, ok := comboByID(combos, "pwn-request")
	if !ok {
		t.Fatalf("expected pwn-request combo, got %+v", combos)
	}
	if c.Severity != ComboCritical {
		t.Errorf("severity = %q, want CRITICAL", c.Severity)
	}
	if c.Scope != ScopeFile {
		t.Errorf("scope = %q, want file", c.Scope)
	}
	if c.File != ".github/workflows/ci.yml" {
		t.Errorf("file = %q, want the workflow path", c.File)
	}
	if len(c.Components) != 2 {
		t.Errorf("components = %d, want 2", len(c.Components))
	}
	// Components must carry the concrete file:line that matched.
	for _, comp := range c.Components {
		if comp.Finding.File != ".github/workflows/ci.yml" {
			t.Errorf("component %s file = %q", comp.RuleID, comp.Finding.File)
		}
	}
	// Stages are ordered and the unmatched WPermWrite / injection stages are dropped.
	if len(c.Stages) != 3 { // checkout, missing-perms, impact
		t.Fatalf("stages = %d, want 3 (%+v)", len(c.Stages), c.Stages)
	}
	for i, s := range c.Stages {
		if s.Order != i {
			t.Errorf("stage %d order = %d", i, s.Order)
		}
	}
	if last := c.Stages[len(c.Stages)-1]; last.RuleID != "" {
		t.Errorf("final stage should be synthetic impact, got rule %q", last.RuleID)
	}
}

func TestDetectToxicCombinations_PwnRequestRepoTokenAcrossFiles(t *testing.T) {
	// Checkout in one workflow; the writable-token ingredient is the repo-wide
	// default-RW-token setting (a different "file"). The repo alternative should
	// still satisfy the token requirement.
	findings := []Finding{
		fnd(RulePPECheckout, ".github/workflows/ci.yml", 10),
		fnd(RuleWPermWrite, "repository settings", 0),
	}
	combos := DetectToxicCombinations(findings)
	if _, ok := comboByID(combos, "pwn-request"); !ok {
		t.Fatalf("expected pwn-request via repo token, got %+v", combos)
	}
}

func TestDetectToxicCombinations_PwnRequestRequiresSameFileCheckout(t *testing.T) {
	// Missing-permissions is file-scoped: a checkout in file A and missing-perms
	// only in file B must NOT form pwn-request (no repo token present).
	findings := []Finding{
		fnd(RulePPECheckout, ".github/workflows/a.yml", 10),
		fnd(RuleMissingPermissions, ".github/workflows/b.yml", 1),
	}
	combos := DetectToxicCombinations(findings)
	if _, ok := comboByID(combos, "pwn-request"); ok {
		t.Fatalf("did not expect pwn-request across files, got %+v", combos)
	}
}

func TestDetectToxicCombinations_PwnRequestOptionalInjectionStage(t *testing.T) {
	base := []Finding{
		fnd(RulePPECheckout, ".github/workflows/ci.yml", 10),
		fnd(RuleMissingPermissions, ".github/workflows/ci.yml", 1),
	}
	without := DetectToxicCombinations(base)
	c1, _ := comboByID(without, "pwn-request")

	with := DetectToxicCombinations(append(base, fnd(RulePPEShellInjection, ".github/workflows/ci.yml", 20)))
	c2, _ := comboByID(with, "pwn-request")

	if len(c2.Stages) != len(c1.Stages)+1 {
		t.Fatalf("optional injection should add one stage: without=%d with=%d", len(c1.Stages), len(c2.Stages))
	}
	if len(c2.Components) != 3 {
		t.Errorf("components with optional = %d, want 3", len(c2.Components))
	}
}

func TestDetectToxicCombinations_PoisonedExfiltrationOrBranch(t *testing.T) {
	cases := []struct {
		name   string
		secret RuleID
	}{
		{"hardcoded", RuleHardcodedSecrets},
		{"pat", RuleLongLivedPAT},
		{"debug", RuleDebugLoggingEnabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := []Finding{
				fnd(RulePPEShellInjection, ".github/workflows/ci.yml", 5),
				fnd(tc.secret, ".github/workflows/ci.yml", 8),
			}
			combos := DetectToxicCombinations(findings)
			c, ok := comboByID(combos, "poisoned-exfiltration")
			if !ok {
				t.Fatalf("expected poisoned-exfiltration for %s, got %+v", tc.name, combos)
			}
			if c.Severity != ComboCritical {
				t.Errorf("severity = %q, want CRITICAL", c.Severity)
			}
		})
	}
}

func TestDetectToxicCombinations_InjectionAloneIsNotACombo(t *testing.T) {
	findings := []Finding{fnd(RulePPEShellInjection, ".github/workflows/ci.yml", 5)}
	combos := DetectToxicCombinations(findings)
	if _, ok := comboByID(combos, "poisoned-exfiltration"); ok {
		t.Fatalf("injection alone should not form poisoned-exfiltration, got %+v", combos)
	}
}

func TestDetectToxicCombinations_InjectedRunnerTakeover(t *testing.T) {
	// Shell injection in a workflow that also runs on a self-hosted runner:
	// untrusted input becomes RCE on durable infrastructure (CRITICAL, file-scoped).
	findings := []Finding{
		fnd(RulePPEShellInjection, ".github/workflows/ci.yml", 12),
		fnd(RuleSelfHostedRunners, ".github/workflows/ci.yml", 4),
	}
	combos := DetectToxicCombinations(findings)
	c, ok := comboByID(combos, "injected-runner-takeover")
	if !ok {
		t.Fatalf("expected injected-runner-takeover combo, got %+v", combos)
	}
	if c.Severity != ComboCritical {
		t.Errorf("severity = %q, want CRITICAL", c.Severity)
	}
	if c.Scope != ScopeFile {
		t.Errorf("scope = %q, want file", c.Scope)
	}
	if c.File != ".github/workflows/ci.yml" {
		t.Errorf("file = %q, want the workflow path", c.File)
	}
	if c.BreakChainRule != RulePPEShellInjection {
		t.Errorf("break-chain rule = %q, want %q", c.BreakChainRule, RulePPEShellInjection)
	}
	// Two ingredients matched, missing-timeout amplifier absent.
	if len(c.Components) != 2 {
		t.Errorf("components = %d, want 2", len(c.Components))
	}
	if len(c.Stages) != 3 { // injection, self-hosted, impact
		t.Fatalf("stages = %d, want 3 (%+v)", len(c.Stages), c.Stages)
	}
	if last := c.Stages[len(c.Stages)-1]; last.RuleID != "" {
		t.Errorf("final stage should be synthetic impact, got rule %q", last.RuleID)
	}
}

func TestDetectToxicCombinations_InjectedRunnerTakeoverNeedsSameFile(t *testing.T) {
	// Both ingredients are file-scoped: an injectable step in file A and a
	// self-hosted runner only in file B must NOT form the combo — the injected
	// code would not land on the self-hosted runner.
	findings := []Finding{
		fnd(RulePPEShellInjection, ".github/workflows/a.yml", 12),
		fnd(RuleSelfHostedRunners, ".github/workflows/b.yml", 4),
	}
	combos := DetectToxicCombinations(findings)
	if _, ok := comboByID(combos, "injected-runner-takeover"); ok {
		t.Fatalf("did not expect injected-runner-takeover across files, got %+v", combos)
	}
}

func TestDetectToxicCombinations_InjectedRunnerTakeoverTimeoutAmplifier(t *testing.T) {
	base := []Finding{
		fnd(RulePPEShellInjection, ".github/workflows/ci.yml", 12),
		fnd(RuleSelfHostedRunners, ".github/workflows/ci.yml", 4),
	}
	without := DetectToxicCombinations(base)
	c1, _ := comboByID(without, "injected-runner-takeover")

	with := DetectToxicCombinations(append(base, fnd(RuleMissingTimeout, ".github/workflows/ci.yml", 6)))
	c2, _ := comboByID(with, "injected-runner-takeover")

	if len(c2.Stages) != len(c1.Stages)+1 {
		t.Fatalf("optional timeout should add one stage: without=%d with=%d", len(c1.Stages), len(c2.Stages))
	}
	if len(c2.Components) != 3 {
		t.Errorf("components with optional = %d, want 3", len(c2.Components))
	}
}

func TestDetectToxicCombinations_RepoScopeAcrossFiles(t *testing.T) {
	// persistent-supply-chain-foothold is repo-scoped: ingredients in different
	// files still combine into a single combo instance.
	findings := []Finding{
		fnd(RuleUnpinnedAction, ".github/workflows/a.yml", 3),
		fnd(RuleSelfHostedRunners, ".github/workflows/b.yml", 7),
	}
	combos := DetectToxicCombinations(findings)
	c, ok := comboByID(combos, "persistent-supply-chain-foothold")
	if !ok {
		t.Fatalf("expected repo-scoped combo across files, got %+v", combos)
	}
	if c.Scope != ScopeRepo {
		t.Errorf("scope = %q, want repo", c.Scope)
	}
	if c.File != "" {
		t.Errorf("repo combo file = %q, want empty", c.File)
	}
}

func TestDetectToxicCombinations_RepoComboDedup(t *testing.T) {
	// The same repo-scoped ingredients spread across three files must yield
	// exactly one combo instance.
	findings := []Finding{
		fnd(RuleUnpinnedAction, ".github/workflows/a.yml", 3),
		fnd(RuleUnpinnedAction, ".github/workflows/b.yml", 3),
		fnd(RuleUnpinnedAction, ".github/workflows/c.yml", 3),
		fnd(RuleSelfHostedRunners, ".github/workflows/a.yml", 7),
		fnd(RuleSelfHostedRunners, ".github/workflows/b.yml", 7),
	}
	combos := DetectToxicCombinations(findings)
	count := 0
	for _, c := range combos {
		if c.ID == "persistent-supply-chain-foothold" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 repo combo instance, got %d", count)
	}
}

func TestDetectToxicCombinations_DeterministicSeverityOrder(t *testing.T) {
	// A CRITICAL and a HIGH combo present together — CRITICAL must sort first.
	findings := []Finding{
		// pwn-request (CRITICAL)
		fnd(RulePPECheckout, ".github/workflows/ci.yml", 10),
		fnd(RuleMissingPermissions, ".github/workflows/ci.yml", 1),
		// persistent-supply-chain-foothold (HIGH)
		fnd(RuleUnpinnedAction, ".github/workflows/ci.yml", 3),
		fnd(RuleSelfHostedRunners, ".github/workflows/ci.yml", 7),
	}
	combos := DetectToxicCombinations(findings)
	if len(combos) < 2 {
		t.Fatalf("expected at least 2 combos, got %d", len(combos))
	}
	if combos[0].Severity != ComboCritical {
		t.Errorf("first combo severity = %q, want CRITICAL first", combos[0].Severity)
	}
}

func TestDetectToxicCombinations_IgnoresSyntheticFindings(t *testing.T) {
	// SYSTEM findings have an empty RuleID and must never participate.
	findings := []Finding{
		{File: "x.yml", Category: "SYSTEM", Title: "File Parse Error"},
		fnd(RulePPECheckout, ".github/workflows/ci.yml", 10),
	}
	combos := DetectToxicCombinations(findings)
	if _, ok := comboByID(combos, "pwn-request"); ok {
		t.Fatalf("checkout alone (no token) should not form pwn-request, got %+v", combos)
	}
}

func TestDetectToxicCombinations_UntrustedCodeOnSelfHosted(t *testing.T) {
	findings := []Finding{
		fnd(RulePPECheckout, ".github/workflows/ci.yml", 10),
		fnd(RuleSelfHostedRunners, ".github/workflows/build.yml", 7),
	}
	combos := DetectToxicCombinations(findings)
	c, ok := comboByID(combos, "untrusted-code-on-self-hosted")
	if !ok {
		t.Fatalf("expected untrusted-code-on-self-hosted, got %+v", combos)
	}
	if c.Severity != ComboHigh {
		t.Errorf("severity = %q, want HIGH", c.Severity)
	}
	if c.Scope != ScopeFile {
		t.Errorf("scope = %q, want file (anchored on the checkout)", c.Scope)
	}
	// Without the checkout there is no combo.
	if _, ok := comboByID(DetectToxicCombinations(findings[1:]), "untrusted-code-on-self-hosted"); ok {
		t.Fatalf("self-hosted alone should not form the combo")
	}
}

func TestDetectToxicCombinations_SecretExposureInLogs(t *testing.T) {
	findings := []Finding{
		fnd(RuleDebugLoggingEnabled, ".github/workflows/ci.yml", 4),
		fnd(RuleHardcodedSecrets, ".github/workflows/ci.yml", 8),
	}
	c, ok := comboByID(DetectToxicCombinations(findings), "secret-exposure-in-logs")
	if !ok {
		t.Fatalf("expected secret-exposure-in-logs, got %+v", findings)
	}
	if c.Severity != ComboHigh || c.Scope != ScopeFile {
		t.Errorf("severity/scope = %q/%q, want HIGH/file", c.Severity, c.Scope)
	}
	// Different files must not combine (file-scoped).
	split := []Finding{
		fnd(RuleDebugLoggingEnabled, ".github/workflows/a.yml", 4),
		fnd(RuleHardcodedSecrets, ".github/workflows/b.yml", 8),
	}
	if _, ok := comboByID(DetectToxicCombinations(split), "secret-exposure-in-logs"); ok {
		t.Fatalf("debug+secret in different files should not combine")
	}
}

func TestDetectToxicCombinations_UnverifiableRelease(t *testing.T) {
	findings := []Finding{
		fnd(RuleSLSAProvenance, ".github/workflows/release.yml", 12),
		fnd(RuleUnpinnedAction, ".github/workflows/release.yml", 20),
	}
	c, ok := comboByID(DetectToxicCombinations(findings), "unverifiable-release")
	if !ok {
		t.Fatalf("expected unverifiable-release, got %+v", findings)
	}
	if c.Severity != ComboHigh || c.Scope != ScopeRepo {
		t.Errorf("severity/scope = %q/%q, want HIGH/repo", c.Severity, c.Scope)
	}
}

func TestDetectToxicCombinations_GitLabPwnRequest(t *testing.T) {
	for _, secret := range []RuleID{RuleGitLabShellInjection, RuleGitLabHardcodedSecrets, RuleGitLabDebugTrace} {
		findings := []Finding{
			fnd(RuleGitLabMRTarget, ".gitlab-ci.yml", 5),
			fnd(secret, ".gitlab-ci.yml", 9),
		}
		c, ok := comboByID(DetectToxicCombinations(findings), "gl-pwn-request")
		if !ok {
			t.Fatalf("expected gl-pwn-request with %s, got %+v", secret, findings)
		}
		if c.Severity != ComboCritical {
			t.Errorf("severity = %q, want CRITICAL", c.Severity)
		}
	}
	// MR-target alone is not a combo.
	if _, ok := comboByID(DetectToxicCombinations([]Finding{fnd(RuleGitLabMRTarget, ".gitlab-ci.yml", 5)}), "gl-pwn-request"); ok {
		t.Fatalf("mr-target alone should not form gl-pwn-request")
	}
}

func TestDetectToxicCombinations_GitLabPoisonedExfiltration(t *testing.T) {
	for _, secret := range []RuleID{RuleGitLabHardcodedSecrets, RuleGitLabPATSecret, RuleGitLabDebugTrace} {
		findings := []Finding{
			fnd(RuleGitLabShellInjection, ".gitlab-ci.yml", 5),
			fnd(secret, ".gitlab-ci.yml", 9),
		}
		if _, ok := comboByID(DetectToxicCombinations(findings), "gl-poisoned-exfiltration"); !ok {
			t.Fatalf("expected gl-poisoned-exfiltration with %s, got %+v", secret, findings)
		}
	}
}

func TestDetectToxicCombinations_GitLabPersistentFoothold(t *testing.T) {
	findings := []Finding{
		fnd(RuleGitLabUnpinnedInclude, ".gitlab-ci.yml", 2),
		fnd(RuleGitLabSelfHostedTags, ".gitlab-ci.yml", 11),
	}
	c, ok := comboByID(DetectToxicCombinations(findings), "gl-persistent-foothold")
	if !ok {
		t.Fatalf("expected gl-persistent-foothold, got %+v", findings)
	}
	if c.Severity != ComboHigh || c.Scope != ScopeRepo {
		t.Errorf("severity/scope = %q/%q, want HIGH/repo", c.Severity, c.Scope)
	}
}
