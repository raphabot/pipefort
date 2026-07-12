package scanner

import "testing"

func boolp(b bool) *bool { return &b }
func intp(i int) *int    { return &i }

func hasRuleIn(findings []Finding, id RuleID) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestScanGitLabProjectSettings(t *testing.T) {
	// Worst-case project: unprotected default branch, merges without pipeline,
	// public pipelines, zero approvals.
	worst := GitLabProjectContext{
		DefaultBranch:                    "main",
		BranchProtectionFetched:          true,
		DefaultBranchProtected:           false,
		OnlyAllowMergeIfPipelineSucceeds: boolp(false),
		PublicBuilds:                     boolp(true),
		ApprovalsBeforeMerge:             intp(0),
	}
	f := ScanGitLabProjectSettings(worst)
	for _, want := range []RuleID{
		RuleGitLabBPMissing,
		RuleGitLabMergeNoPipeline,
		RuleGitLabPublicPipelines,
		RuleGitLabNoApprovals,
	} {
		if !hasRuleIn(f, want) {
			t.Errorf("expected %s to fire, got %+v", want, f)
		}
	}
	// Every finding carries the settings-file label and a confidence.
	for _, x := range f {
		if x.File != SettingsFile {
			t.Errorf("settings finding not labeled SettingsFile: %+v", x)
		}
		if x.Confidence == "" {
			t.Errorf("settings finding missing confidence: %s", x.RuleID)
		}
	}
}

func TestScanGitLabProjectSettingsForcePush(t *testing.T) {
	// Protected but force-push allowed → force-push rule, not the missing one.
	ctx := GitLabProjectContext{
		DefaultBranch:                "main",
		BranchProtectionFetched:      true,
		DefaultBranchProtected:       true,
		DefaultBranchAllowsForcePush: true,
	}
	f := ScanGitLabProjectSettings(ctx)
	if !hasRuleIn(f, RuleGitLabBPForcePush) || hasRuleIn(f, RuleGitLabBPMissing) {
		t.Errorf("expected force-push only, got %+v", f)
	}
}

func TestScanGitLabProjectSettingsHardened(t *testing.T) {
	// A hardened project fires nothing.
	ctx := GitLabProjectContext{
		DefaultBranch:                    "main",
		BranchProtectionFetched:          true,
		DefaultBranchProtected:           true,
		DefaultBranchAllowsForcePush:     false,
		OnlyAllowMergeIfPipelineSucceeds: boolp(true),
		PublicBuilds:                     boolp(false),
		ApprovalsBeforeMerge:             intp(2),
	}
	if f := ScanGitLabProjectSettings(ctx); len(f) != 0 {
		t.Errorf("hardened project should be clean, got %+v", f)
	}
}

func TestScanGitLabProjectSettingsGracefulNils(t *testing.T) {
	// Free tier: approvals unavailable (nil), protected branches not fetched.
	// Those rules must be skipped rather than firing on a zero value.
	ctx := GitLabProjectContext{
		DefaultBranch:           "main",
		BranchProtectionFetched: false, // couldn't read → skip BP rules
		// OnlyAllowMerge... nil, PublicBuilds nil, ApprovalsBeforeMerge nil
	}
	if f := ScanGitLabProjectSettings(ctx); len(f) != 0 {
		t.Errorf("unfetched settings must not fire, got %+v", f)
	}
}

func TestGitLabMissingResourceGroup(t *testing.T) {
	// A deploy job with an environment but no resource_group is flagged.
	gl := `deploy:
  stage: deploy
  environment:
    name: production
  script:
    - ./deploy.sh
`
	findings, err := ScanBytes(".gitlab-ci.yml", []byte(gl))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if !hasRuleIn(findings, RuleGitLabMissingResGroup) {
		t.Errorf("expected missing-resource-group finding, got %+v", findings)
	}

	// With a resource_group → clean.
	ok := `deploy:
  environment:
    name: production
  resource_group: production
  script:
    - ./deploy.sh
`
	findings, _ = ScanBytes(".gitlab-ci.yml", []byte(ok))
	if hasRuleIn(findings, RuleGitLabMissingResGroup) {
		t.Errorf("resource_group present should be clean, got %+v", findings)
	}
}
