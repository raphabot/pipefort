package scanner

import "fmt"

// GitLabProjectContext is the GitLab project configuration the settings audit
// inspects. It is the GitLab analog of RepositoryContext (which is
// GitHub-shaped); the API layer fetches it and hands it to
// ScanGitLabProjectSettings. Pointer fields distinguish "not fetched / not
// available on this tier" (nil) from a real value.
type GitLabProjectContext struct {
	ProjectPath   string
	WebURL        string
	DefaultBranch string

	// OnlyAllowMergeIfPipelineSucceeds mirrors the project setting of the same
	// name; nil when the project payload didn't include it.
	OnlyAllowMergeIfPipelineSucceeds *bool
	// PublicBuilds is the "public pipelines" project setting.
	PublicBuilds *bool
	// ApprovalsBeforeMerge is the required approval count; nil when the
	// approvals API is unavailable (Free tier returns 404).
	ApprovalsBeforeMerge *int

	// DefaultBranchProtected is true when the default branch has a Protected
	// Branch entry. DefaultBranchAllowsForcePush reflects that entry's
	// allow_force_push. Both are meaningful only when protected-branch data was
	// fetched (BranchProtectionFetched).
	BranchProtectionFetched      bool
	DefaultBranchProtected       bool
	DefaultBranchAllowsForcePush bool
}

// ScanGitLabProjectSettings runs the GitLab project-configuration checks and
// returns the findings. Each finding carries the synthetic SettingsFile path
// and Platform-gitlab rule ids so the UI groups them like the GitHub settings
// audit. Mirrors ScanRepositorySettings's hardcoded-sequence style.
func ScanGitLabProjectSettings(ctx GitLabProjectContext) []Finding {
	var findings []Finding

	if ctx.BranchProtectionFetched {
		if !ctx.DefaultBranchProtected {
			findings = append(findings, glSettingFinding(RuleGitLabBPMissing, SeverityHigh,
				"GitLab default branch is not protected",
				fmt.Sprintf("The default branch %q has no Protected Branch entry — anyone with push access can commit directly and rewrite history.", ctx.DefaultBranch),
				"Protect the default branch under Settings → Repository → Protected branches (disallow force push, require merge via MR)."))
		} else if ctx.DefaultBranchAllowsForcePush {
			findings = append(findings, glSettingFinding(RuleGitLabBPForcePush, SeverityHigh,
				"GitLab protected default branch allows force push",
				fmt.Sprintf("The protected default branch %q permits force pushes, allowing history rewrites that erase the record of what was merged.", ctx.DefaultBranch),
				"Disable 'Allowed to force push' on the default branch's protected-branch rule."))
		}
	}

	if ctx.OnlyAllowMergeIfPipelineSucceeds != nil && !*ctx.OnlyAllowMergeIfPipelineSucceeds {
		findings = append(findings, glSettingFinding(RuleGitLabMergeNoPipeline, SeverityMedium,
			"GitLab merges allowed without a passing pipeline",
			"'Pipelines must succeed' is off, so merge requests can merge even when CI (including security checks) fails.",
			"Enable Settings → Merge requests → 'Pipelines must succeed'."))
	}

	if ctx.PublicBuilds != nil && *ctx.PublicBuilds {
		f := glSettingFinding(RuleGitLabPublicPipelines, SeverityMedium,
			"GitLab public pipelines expose job logs and artifacts",
			"Public pipelines let non-members view CI job logs and download artifacts, which can leak secrets echoed in logs or build outputs.",
			"Turn off Settings → CI/CD → General pipelines → 'Public pipelines'.")
		f.Category = "CICD-SEC-4"
		findings = append(findings, f)
	}

	if ctx.ApprovalsBeforeMerge != nil && *ctx.ApprovalsBeforeMerge < 1 {
		findings = append(findings, glSettingFinding(RuleGitLabNoApprovals, SeverityMedium,
			"GitLab merge requests require no approvals",
			"The project requires zero approvals before merge, so a single actor can merge unreviewed changes.",
			"Require at least one (ideally two) approvals under Settings → Merge requests → Approval rules."))
	}

	return StampConfidence(findings)
}

func glSettingFinding(rule RuleID, sev Severity, title, desc, rec string) Finding {
	return Finding{
		File:           SettingsFile,
		Line:           0,
		Column:         0,
		Severity:       sev,
		Category:       "CICD-SEC-1",
		RuleID:         rule,
		Title:          title,
		Description:    desc,
		Recommendation: rec,
	}
}
