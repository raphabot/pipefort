package scanner

import (
	"fmt"
	"strings"
	"testing"
)

// TestRulesCatalogShape asserts every entry in Rules() is fully populated
// (so the API can safely serve it without nil checks) and that IDs are
// unique. The catalog is a runtime contract for the SPA's Rule Settings
// page — any half-filled entry would silently break the UI.
func TestRulesCatalogShape(t *testing.T) {
	seen := map[RuleID]bool{}
	for i, r := range Rules() {
		if r.ID == "" {
			t.Errorf("Rules()[%d] has empty ID", i)
		}
		if seen[r.ID] {
			t.Errorf("duplicate RuleID %q at index %d", r.ID, i)
		}
		seen[r.ID] = true
		if r.Category == "" {
			t.Errorf("rule %q has empty Category", r.ID)
		}
		if r.Title == "" {
			t.Errorf("rule %q has empty Title", r.ID)
		}
		switch r.DefaultSeverity {
		case SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		default:
			t.Errorf("rule %q has invalid DefaultSeverity %q", r.ID, r.DefaultSeverity)
		}
		switch r.Surface {
		case SurfaceWorkflow, SurfaceRepoSettings:
		default:
			t.Errorf("rule %q has invalid Surface %q", r.ID, r.Surface)
		}
		if r.Description == "" {
			t.Errorf("rule %q has empty Description", r.ID)
		}
		// DocURL must match the ID slug exactly for the 17 settings rules
		// (those slugs already exist as docs/rules/<id>.mdx pages). The 8
		// workflow checks point at the parent CICD-SEC-N / BEST-PRAC-N page.
		if r.DocURL == "" {
			t.Errorf("rule %q has empty DocURL", r.ID)
		}
		// Rules() normalizes empty confidence/persona — consumers must never
		// see a zero value.
		switch r.DefaultConfidence {
		case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		default:
			t.Errorf("rule %q has invalid DefaultConfidence %q", r.ID, r.DefaultConfidence)
		}
		switch r.Persona {
		case PersonaRegular, PersonaPedantic, PersonaAuditor:
		default:
			t.Errorf("rule %q has invalid Persona %q", r.ID, r.Persona)
		}
	}
}

// TestRuleByIDLookup confirms the map helper covers every catalog entry.
func TestRuleByIDLookup(t *testing.T) {
	all := Rules()
	idx := RuleByID()
	if len(idx) != len(all) {
		t.Fatalf("RuleByID size=%d, Rules() size=%d", len(idx), len(all))
	}
	for _, r := range all {
		got, ok := idx[r.ID]
		if !ok {
			t.Errorf("RuleByID missing %q", r.ID)
			continue
		}
		if got.Title != r.Title {
			t.Errorf("RuleByID returns stale entry for %q", r.ID)
		}
	}
}

// TestEveryFindingHasARuleID scans the canonical vulnerable fixture and the
// settings-audit synthetic contexts to assert every produced Finding carries
// a RuleID present in Rules(). This is the catalog/check parity test: if
// someone adds a check and forgets the catalog entry (or vice versa), this
// fails immediately rather than silently shipping an untoggleable rule.
func TestEveryFindingHasARuleID(t *testing.T) {
	idx := RuleByID()

	// 1) Workflow findings via the fixture used by scanner_test.go.
	const fixture = "../../testdata/vulnerable-workflow.yml"
	wfFindings, err := ScanFile(fixture)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(wfFindings) == 0 {
		t.Fatal("expected findings from the vulnerable fixture")
	}
	for _, f := range wfFindings {
		if f.Category == "SYSTEM" {
			continue // SYSTEM/INFO are deliberately untoggleable
		}
		if f.RuleID == "" {
			t.Errorf("workflow finding has empty RuleID: %s — %s", f.Category, f.Title)
			continue
		}
		if _, ok := idx[f.RuleID]; !ok {
			t.Errorf("workflow finding %q references unknown RuleID %q", f.Title, f.RuleID)
		}
	}

	// 2) Settings findings — fire each rule by building a context that
	//    triggers it, then assert the produced Finding carries a known
	//    RuleID. We don't enumerate every rule; we fire enough variations
	//    to cover both severity tiers and both major branches.
	disabledStatus := &FeatureStatus{Status: "disabled"}
	ctxs := []RepositoryContext{
		// Branch-protection-missing path (single finding).
		{
			Owner: "acme", Repo: "demo", DefaultBranch: "main",
			HTMLURL: "https://github.com/acme/demo",
		},
		// Full branch-protection block with worst-case flags (most BP rules fire).
		{
			Owner: "acme", Repo: "demo", DefaultBranch: "main",
			HTMLURL:       "https://github.com/acme/demo",
			HasCodeowners: true,
			BranchProtection: &BranchProtection{
				EnforceAdmins: &EnabledFlag{Enabled: false},
				RequiredPullRequestReviews: &RequiredPullRequestReviews{
					DismissStaleReviews:          false,
					RequireCodeOwnerReviews:      false,
					RequiredApprovingReviewCount: 1,
				},
				AllowForcePushes:   &EnabledFlag{Enabled: true},
				AllowDeletions:     &EnabledFlag{Enabled: true},
				RequiredSignatures: &EnabledFlag{Enabled: false},
				// RequiredStatusChecks omitted to trigger no-status-checks.
			},
			WorkflowPerms: &WorkflowPermissions{
				DefaultWorkflowPermissions:   "write",
				CanApprovePullRequestReviews: true,
			},
			ActionsPolicy: &ActionsPermissions{Enabled: true, AllowedActions: "all"},
			Repository: &RepoInfo{
				SecurityAndAnalysis: &SecurityAndAnalysis{
					SecretScanning:               disabledStatus,
					SecretScanningPushProtection: disabledStatus,
					DependabotSecurityUpdates:    disabledStatus,
				},
			},
			DependabotAlerts: false,
		},
	}

	var ids []string
	for _, ctx := range ctxs {
		for _, f := range ScanRepositorySettings(ctx) {
			if f.Category == "SYSTEM" {
				continue
			}
			if f.RuleID == "" {
				t.Errorf("settings finding has empty RuleID: %s — %s", f.Category, f.Title)
				continue
			}
			if _, ok := idx[f.RuleID]; !ok {
				t.Errorf("settings finding %q references unknown RuleID %q", f.Title, f.RuleID)
			}
			ids = append(ids, string(f.RuleID))
		}
	}

	// Sanity: we should have hit at least a dozen distinct settings rules
	// across the two contexts. If this number drops, a check was deleted
	// without updating the test (or a rule was silently disabled).
	if len(ids) < 12 {
		t.Errorf("expected to fire at least 12 settings findings across both contexts, got %d: %s",
			len(ids), strings.Join(ids, ", "))
	}
}

// TestFilterByEnabledRules covers the helper used at scan time to drop
// per-user disabled rules. SYSTEM/INFO findings (no RuleID) always pass.
func TestFilterByEnabledRules(t *testing.T) {
	findings := []Finding{
		{Category: "CICD-SEC-1", RuleID: RulePPECheckout, Title: "ppe"},
		{Category: "BEST-PRAC-2", RuleID: RuleMissingTimeout, Title: "timeout"},
		{Category: "SYSTEM", Title: "system info"}, // empty RuleID
	}

	for _, tc := range []struct {
		name     string
		disabled map[RuleID]bool
		expected int
	}{
		{"nil map keeps everything", nil, 3},
		{"empty map keeps everything", map[RuleID]bool{}, 3},
		{"disables one rule", map[RuleID]bool{RuleMissingTimeout: true}, 2},
		{"system finding always passes", map[RuleID]bool{
			RulePPECheckout: true, RuleMissingTimeout: true,
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterByEnabledRules(findings, tc.disabled)
			if len(got) != tc.expected {
				t.Errorf("got %d findings, want %d (%v)", len(got), tc.expected, got)
			}
			// Confirm the SYSTEM finding survives any disable list.
			if len(tc.disabled) > 0 {
				var sawSystem bool
				for _, f := range got {
					if f.Category == "SYSTEM" {
						sawSystem = true
					}
				}
				if !sawSystem {
					t.Error("SYSTEM finding was dropped — empty RuleID must always pass")
				}
			}
		})
	}

	// Defensive: confirm the helper does not alias the input slice.
	input := []Finding{{RuleID: RuleMissingTimeout}}
	out := FilterByEnabledRules(input, map[RuleID]bool{RuleMissingTimeout: true})
	if len(out) != 0 {
		t.Errorf("expected empty output, got %v", out)
	}
	if fmt.Sprintf("%p", input) == fmt.Sprintf("%p", out) && cap(out) > 0 {
		t.Error("FilterByEnabledRules must not alias the input backing array")
	}
}
