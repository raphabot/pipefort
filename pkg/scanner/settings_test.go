package scanner

import (
	"strings"
	"testing"
)

// secureContext returns a RepositoryContext where every settings rule should
// pass — used as the "no findings" baseline. Per-rule tests start from this
// and mutate one field at a time so each test isolates a single rule.
func secureContext() RepositoryContext {
	return RepositoryContext{
		Owner:         "acme",
		Repo:          "widgets",
		DefaultBranch: "main",
		HTMLURL:       "https://github.com/acme/widgets",
		Repository: &RepoInfo{
			Private:       false,
			Visibility:    "public",
			DefaultBranch: "main",
			SecurityAndAnalysis: &SecurityAndAnalysis{
				SecretScanning:               &FeatureStatus{Status: "enabled"},
				SecretScanningPushProtection: &FeatureStatus{Status: "enabled"},
				DependabotSecurityUpdates:    &FeatureStatus{Status: "enabled"},
			},
		},
		BranchProtection: &BranchProtection{
			EnforceAdmins: &EnabledFlag{Enabled: true},
			RequiredPullRequestReviews: &RequiredPullRequestReviews{
				DismissStaleReviews:          true,
				RequireCodeOwnerReviews:      true,
				RequiredApprovingReviewCount: 2,
			},
			RequiredStatusChecks: &RequiredStatusChecks{Strict: true},
			RequiredSignatures:   &EnabledFlag{Enabled: true},
			AllowForcePushes:     &EnabledFlag{Enabled: false},
			AllowDeletions:       &EnabledFlag{Enabled: false},
		},
		WorkflowPerms: &WorkflowPermissions{
			DefaultWorkflowPermissions:   "read",
			CanApprovePullRequestReviews: false,
		},
		ActionsPolicy:    &ActionsPermissions{Enabled: true, AllowedActions: "selected"},
		DependabotAlerts: true,
		HasCodeowners:    true,
	}
}

func TestSecureContextProducesNoFindings(t *testing.T) {
	findings := ScanRepositorySettings(secureContext())
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("unexpected finding for secure context: %s — %s", f.Category, f.Title)
		}
	}
}

// findingFor runs the audit and returns the first finding whose title contains
// substr, or fails the test if none match.
func findingFor(t *testing.T, ctx RepositoryContext, substr string) Finding {
	t.Helper()
	for _, f := range ScanRepositorySettings(ctx) {
		if strings.Contains(f.Title, substr) {
			return f
		}
	}
	t.Fatalf("expected a finding containing %q, got none", substr)
	return Finding{}
}

func assertFinding(t *testing.T, f Finding, wantCategory string, wantSeverity Severity) {
	t.Helper()
	if f.Category != wantCategory {
		t.Errorf("category: want %s, got %s", wantCategory, f.Category)
	}
	if f.Severity != wantSeverity {
		t.Errorf("severity: want %s, got %s", wantSeverity, f.Severity)
	}
	if f.File != SettingsFile {
		t.Errorf("file: want %q, got %q", SettingsFile, f.File)
	}
	if f.Line != 0 || f.Column != 0 {
		t.Errorf("line/column should be 0 for settings findings, got %d:%d", f.Line, f.Column)
	}
}

// --- branch protection ----------------------------------------------------

func TestBranchProtectionMissing(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection = nil
	f := findingFor(t, ctx, "no branch protection rule")
	assertFinding(t, f, "CICD-SEC-1", SeverityHigh)
}

func TestBranchProtectionUnavailableOnPlan(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection = nil
	ctx.BranchProtectionUnavailable = true
	// Reported as INFO (not the HIGH "no protection rule") because the owner
	// can't enable it without upgrading the plan.
	f := findingFor(t, ctx, "unavailable on this repository's plan")
	assertFinding(t, f, "CICD-SEC-1", SeverityInfo)
	if f.RuleID != RuleBPMissing {
		t.Errorf("rule ID: want %s, got %s", RuleBPMissing, f.RuleID)
	}
	// It must not also raise the HIGH missing-protection finding.
	for _, other := range ScanRepositorySettings(ctx) {
		if strings.Contains(other.Title, "no branch protection rule") {
			t.Errorf("did not expect the HIGH missing-protection finding when unavailable on plan")
		}
	}
}

func TestBranchProtectionForcePush(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.AllowForcePushes.Enabled = true
	f := findingFor(t, ctx, "allows force pushes")
	assertFinding(t, f, "CICD-SEC-1", SeverityHigh)
}

func TestBranchProtectionDeletion(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.AllowDeletions.Enabled = true
	f := findingFor(t, ctx, "can be deleted")
	assertFinding(t, f, "CICD-SEC-1", SeverityHigh)
}

func TestBranchProtectionNoReview(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.RequiredPullRequestReviews = nil
	f := findingFor(t, ctx, "does not require pull request reviews")
	assertFinding(t, f, "CICD-SEC-1", SeverityHigh)
}

func TestBranchProtectionFewReviewers(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.RequiredPullRequestReviews.RequiredApprovingReviewCount = 1
	f := findingFor(t, ctx, "fewer than 2 approving reviews")
	assertFinding(t, f, "CICD-SEC-1", SeverityMedium)
}

func TestBranchProtectionStaleReviews(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.RequiredPullRequestReviews.DismissStaleReviews = false
	f := findingFor(t, ctx, "stale reviews")
	assertFinding(t, f, "CICD-SEC-1", SeverityMedium)
}

func TestBranchProtectionNoStatusChecks(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.RequiredStatusChecks = nil
	f := findingFor(t, ctx, "status checks")
	assertFinding(t, f, "CICD-SEC-1", SeverityMedium)
}

func TestBranchProtectionAdminBypass(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.EnforceAdmins.Enabled = false
	f := findingFor(t, ctx, "Admins can bypass")
	assertFinding(t, f, "CICD-SEC-1", SeverityHigh)
}

func TestBranchProtectionNoCodeownersReview(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.RequiredPullRequestReviews.RequireCodeOwnerReviews = false
	f := findingFor(t, ctx, "CODEOWNERS exists")
	assertFinding(t, f, "CICD-SEC-1", SeverityLow)
}

func TestBranchProtectionNoCodeownersReviewSkippedWithoutFile(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.RequiredPullRequestReviews.RequireCodeOwnerReviews = false
	ctx.HasCodeowners = false // no CODEOWNERS file -> rule is moot
	for _, f := range ScanRepositorySettings(ctx) {
		if strings.Contains(f.Title, "CODEOWNERS exists") {
			t.Fatalf("CODEOWNERS-review finding should be suppressed when no CODEOWNERS file exists")
		}
	}
}

func TestBranchProtectionNoSignedCommits(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection.RequiredSignatures.Enabled = false
	f := findingFor(t, ctx, "signed commits")
	assertFinding(t, f, "CICD-SEC-1", SeverityLow)
}

// --- workflow permissions -------------------------------------------------

func TestWorkflowPermissionsWrite(t *testing.T) {
	ctx := secureContext()
	ctx.WorkflowPerms.DefaultWorkflowPermissions = "write"
	f := findingFor(t, ctx, "GITHUB_TOKEN permissions are read-write")
	assertFinding(t, f, "CICD-SEC-4", SeverityHigh)
}

func TestWorkflowPermissionsPRApprove(t *testing.T) {
	ctx := secureContext()
	ctx.WorkflowPerms.CanApprovePullRequestReviews = true
	f := findingFor(t, ctx, "Actions can approve pull requests")
	assertFinding(t, f, "CICD-SEC-4", SeverityHigh)
}

// --- Actions allowlist ----------------------------------------------------

func TestActionsAllAllowed(t *testing.T) {
	ctx := secureContext()
	ctx.ActionsPolicy.AllowedActions = "all"
	f := findingFor(t, ctx, "All GitHub Actions and reusable workflows are allowed")
	assertFinding(t, f, "CICD-SEC-5", SeverityMedium)
}

func TestActionsAllAllowedSkippedWhenDisabled(t *testing.T) {
	ctx := secureContext()
	ctx.ActionsPolicy.Enabled = false
	ctx.ActionsPolicy.AllowedActions = "all" // irrelevant — Actions is off
	for _, f := range ScanRepositorySettings(ctx) {
		if strings.Contains(f.Title, "Actions and reusable workflows are allowed") {
			t.Fatal("rule should not fire when Actions is disabled for the repo")
		}
	}
}

// --- Dependabot -----------------------------------------------------------

func TestDependabotAlertsOff(t *testing.T) {
	ctx := secureContext()
	ctx.DependabotAlerts = false
	f := findingFor(t, ctx, "Dependabot alerts are disabled")
	assertFinding(t, f, "CICD-SEC-3", SeverityMedium)
}

func TestDependabotFixesOff(t *testing.T) {
	ctx := secureContext()
	ctx.Repository.SecurityAndAnalysis.DependabotSecurityUpdates.Status = "disabled"
	f := findingFor(t, ctx, "Dependabot security updates are disabled")
	assertFinding(t, f, "CICD-SEC-3", SeverityLow)
}

// --- secret scanning ------------------------------------------------------

func TestSecretScanningOff(t *testing.T) {
	ctx := secureContext()
	ctx.Repository.SecurityAndAnalysis.SecretScanning.Status = "disabled"
	f := findingFor(t, ctx, "Secret scanning is disabled")
	assertFinding(t, f, "CICD-SEC-6", SeverityMedium)
}

func TestSecretScanningSilentWhenUnsupported(t *testing.T) {
	// Private repo without GHAS: GitHub omits secret_scanning entirely. We
	// must not fire a "disabled" finding in that case (it's just unavailable).
	ctx := secureContext()
	ctx.Repository.SecurityAndAnalysis.SecretScanning = nil
	for _, f := range ScanRepositorySettings(ctx) {
		if strings.Contains(f.Title, "Secret scanning is disabled") {
			t.Fatal("rule should not fire when the feature is not surfaced")
		}
	}
}

func TestSecretPushProtectionOff(t *testing.T) {
	ctx := secureContext()
	ctx.Repository.SecurityAndAnalysis.SecretScanningPushProtection.Status = "disabled"
	f := findingFor(t, ctx, "push protection is disabled")
	assertFinding(t, f, "CICD-SEC-6", SeverityHigh)
}

// --- ruleset filter behaviour --------------------------------------------

func TestSettingsFindingsFlowIntoOwaspRuleset(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection = nil       // BP-MISSING (CICD-SEC-1)
	ctx.DependabotAlerts = false     // DEPENDABOT-ALERTS-OFF (CICD-SEC-3)
	all := ScanRepositorySettings(ctx)
	owasp := FilterFindings(all, "owasp")
	if len(owasp) != len(all) {
		t.Errorf("all settings findings have CICD-SEC-* prefix and should survive the owasp filter, got %d/%d", len(owasp), len(all))
	}
}

// --- remediation links ----------------------------------------------------

func TestRemediationLinksUseRepoURL(t *testing.T) {
	ctx := secureContext()
	ctx.BranchProtection = nil // triggers BP-MISSING with a remediation link
	f := findingFor(t, ctx, "no branch protection rule")
	if !strings.Contains(f.Recommendation, "https://github.com/acme/widgets/settings/branches") {
		t.Errorf("recommendation should link to the repo's settings page, got: %s", f.Recommendation)
	}
}

func TestRemediationLinksFallBackToOwnerRepo(t *testing.T) {
	ctx := secureContext()
	ctx.HTMLURL = "" // CLI may not know the canonical URL
	ctx.BranchProtection = nil
	f := findingFor(t, ctx, "no branch protection rule")
	if !strings.Contains(f.Recommendation, "github.com/acme/widgets/settings/branches") {
		t.Errorf("recommendation should fall back to owner/repo, got: %s", f.Recommendation)
	}
}
