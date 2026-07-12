package scanner

import (
	"fmt"
)

// SettingsFile is the synthetic Finding.File value used for all repository
// configuration findings (those that come from the GitHub API, not from a
// workflow YAML). Reporters and the web SPA recognize this exact value and
// render the findings apart from per-file findings.
const SettingsFile = "<repository settings>"

// RepositoryContext is the bundle of GitHub-side configuration the
// settings-audit rules inspect. It mirrors what FetchRepositorySettings
// returns from pkg/api/github.go. Pointer fields are nil when the
// corresponding endpoint returns 404 (or is otherwise unavailable);
// callers must treat nil as "not configured" rather than panicking.
type RepositoryContext struct {
	Owner         string
	Repo          string
	DefaultBranch string
	HTMLURL       string // e.g. https://github.com/{owner}/{repo} — used to build remediation links

	Repository       *RepoInfo
	BranchProtection *BranchProtection
	WorkflowPerms    *WorkflowPermissions
	ActionsPolicy    *ActionsPermissions
	DependabotAlerts bool // true == GitHub returned 204 ("enabled")
	HasCodeowners    bool // true when any of CODEOWNERS / .github/CODEOWNERS / docs/CODEOWNERS exists

	// BranchProtectionUnavailable is true when GitHub refused to serve branch
	// protection because the repository's plan doesn't support protected
	// branches (private repo on a free plan), as opposed to it simply being
	// unconfigured (BranchProtection == nil with this false). The audit reports
	// this as an INFO note instead of a HIGH "no protection" finding the owner
	// can't act on without upgrading.
	BranchProtectionUnavailable bool
}

// RepoInfo is the subset of GET /repos/{owner}/{repo} the settings audit cares
// about. SecurityAndAnalysis is only present for repos where GitHub has decided
// to surface the feature toggles (always for public, conditionally for private).
type RepoInfo struct {
	Private             bool                 `json:"private"`
	Visibility          string               `json:"visibility"` // "public" | "private" | "internal"
	DefaultBranch       string               `json:"default_branch"`
	SecurityAndAnalysis *SecurityAndAnalysis `json:"security_and_analysis,omitempty"`
}

// SecurityAndAnalysis mirrors the nested object GitHub returns when the
// repository has any of the related features available. Each sub-field is
// itself nullable — secret scanning, for example, is only reported on repos
// where GitHub Advanced Security applies.
type SecurityAndAnalysis struct {
	SecretScanning               *FeatureStatus `json:"secret_scanning,omitempty"`
	SecretScanningPushProtection *FeatureStatus `json:"secret_scanning_push_protection,omitempty"`
	DependabotSecurityUpdates    *FeatureStatus `json:"dependabot_security_updates,omitempty"`
}

// FeatureStatus is GitHub's `{"status": "enabled" | "disabled"}` shape.
type FeatureStatus struct {
	Status string `json:"status"`
}

// BranchProtection is the subset of GET /repos/.../branches/{branch}/protection
// the rules need. Nested pointer fields follow GitHub's convention of omitting
// the sub-object entirely when the policy is not in force (e.g.
// RequiredPullRequestReviews == nil means "PR reviews are not required").
type BranchProtection struct {
	EnforceAdmins              *EnabledFlag                `json:"enforce_admins,omitempty"`
	RequiredPullRequestReviews *RequiredPullRequestReviews `json:"required_pull_request_reviews,omitempty"`
	RequiredStatusChecks       *RequiredStatusChecks       `json:"required_status_checks,omitempty"`
	RequiredSignatures         *EnabledFlag                `json:"required_signatures,omitempty"`
	AllowForcePushes           *EnabledFlag                `json:"allow_force_pushes,omitempty"`
	AllowDeletions             *EnabledFlag                `json:"allow_deletions,omitempty"`
}

// EnabledFlag is GitHub's recurring `{"enabled": bool}` envelope.
type EnabledFlag struct {
	Enabled bool `json:"enabled"`
}

// RequiredPullRequestReviews mirrors the branch-protection sub-object.
type RequiredPullRequestReviews struct {
	DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
	RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
}

// RequiredStatusChecks mirrors the branch-protection sub-object.
type RequiredStatusChecks struct {
	Strict bool `json:"strict"`
}

// WorkflowPermissions mirrors GET /repos/.../actions/permissions/workflow.
type WorkflowPermissions struct {
	DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`     // "read" | "write"
	CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"` // self-approval
}

// ActionsPermissions mirrors GET /repos/.../actions/permissions.
type ActionsPermissions struct {
	Enabled        bool   `json:"enabled"`
	AllowedActions string `json:"allowed_actions"` // "all" | "local_only" | "selected"
}

// ScanRepositorySettings runs every repository-settings audit rule against the
// fetched context and returns the resulting findings. It mirrors ScanBytes's
// hardcoded-sequence style at scanner.go so a new rule means "add a line
// here", with no registry to update.
func ScanRepositorySettings(ctx RepositoryContext) []Finding {
	var findings []Finding

	// CICD-SEC-1 — Insufficient Flow Control (branch protection)
	findings = append(findings, checkBranchProtectionMissing(ctx)...)
	if ctx.BranchProtection != nil { // the per-field checks only make sense when a rule exists
		findings = append(findings, checkBranchProtectionForcePush(ctx)...)
		findings = append(findings, checkBranchProtectionDeletion(ctx)...)
		findings = append(findings, checkBranchProtectionNoReview(ctx)...)
		findings = append(findings, checkBranchProtectionFewReviewers(ctx)...)
		findings = append(findings, checkBranchProtectionStaleReviews(ctx)...)
		findings = append(findings, checkBranchProtectionNoStatusChecks(ctx)...)
		findings = append(findings, checkBranchProtectionAdminBypass(ctx)...)
		findings = append(findings, checkBranchProtectionNoCodeownersReview(ctx)...)
		findings = append(findings, checkBranchProtectionNoSignedCommits(ctx)...)
	}

	// CICD-SEC-4 — Poisoned Pipeline Execution (Actions runtime settings)
	findings = append(findings, checkWorkflowPermissionsWrite(ctx)...)
	findings = append(findings, checkWorkflowPermissionsPRApprove(ctx)...)

	// CICD-SEC-5 — Insufficient PBAC (Actions allowlist)
	findings = append(findings, checkActionsAllAllowed(ctx)...)

	// CICD-SEC-3 — Dependency Chain Abuse (Dependabot)
	findings = append(findings, checkDependabotAlertsOff(ctx)...)
	findings = append(findings, checkDependabotFixesOff(ctx)...)

	// CICD-SEC-6 — Insufficient Credential Hygiene (secret scanning)
	findings = append(findings, checkSecretScanningOff(ctx)...)
	findings = append(findings, checkSecretPushProtectionOff(ctx)...)

	return StampConfidence(findings)
}

// settingFinding stamps the synthetic file label, zero coordinates, and the
// caller-supplied severity/category/RuleID/title/etc. onto a Finding. All
// repository-settings findings flow through here so the field shape stays
// uniform and every check carries its own RuleID for the rule-settings filter.
func settingFinding(severity Severity, category string, ruleID RuleID, title, description, recommendation string) Finding {
	return Finding{
		File:           SettingsFile,
		Line:           0,
		Column:         0,
		Severity:       severity,
		Category:       category,
		RuleID:         ruleID,
		Title:          title,
		Description:    description,
		Recommendation: recommendation,
	}
}

// settingsURL is the canonical github.com link for a remediation pointer. We
// prefer the repo's own settings UI rather than the API docs.
func settingsURL(ctx RepositoryContext, path string) string {
	if ctx.HTMLURL != "" {
		return ctx.HTMLURL + path
	}
	return fmt.Sprintf("https://github.com/%s/%s%s", ctx.Owner, ctx.Repo, path)
}

// --- CICD-SEC-1 — branch protection ---------------------------------------

func checkBranchProtectionMissing(ctx RepositoryContext) []Finding {
	if ctx.BranchProtection != nil {
		return nil
	}
	if ctx.BranchProtectionUnavailable {
		// GitHub won't serve protected branches on this repo's plan, so we
		// can't audit them and the owner can't enable them without upgrading.
		// Report it as INFO rather than a HIGH finding they can't action.
		return []Finding{settingFinding(
			SeverityInfo, "CICD-SEC-1", RuleBPMissing,
			"Branch protection unavailable on this repository's plan",
			fmt.Sprintf(
				"GitHub does not offer branch protection for %q: protected branches on private repositories require a paid plan (GitHub Pro, Team, or Enterprise). Pipefort could not audit branch-protection settings for this repository as a result.",
				ctx.DefaultBranch,
			),
			fmt.Sprintf(
				"Make the repository public, or upgrade the account's GitHub plan, to enable branch protection for %q at %s. The other repository-configuration checks (Actions, Dependabot, secret scanning) still apply.",
				ctx.DefaultBranch, settingsURL(ctx, "/settings/branches"),
			),
		)}
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-1", RuleBPMissing,
		"Default branch has no branch protection rule",
		fmt.Sprintf(
			"The default branch %q has no branch protection rule. Anyone with write access can push directly, force-push over history, or delete the branch — bypassing any review or CI gate.",
			ctx.DefaultBranch,
		),
		fmt.Sprintf(
			"Configure a branch protection rule for %q at %s. At minimum, require a pull request before merging and enforce status checks.",
			ctx.DefaultBranch, settingsURL(ctx, "/settings/branches"),
		),
	)}
}

func checkBranchProtectionForcePush(ctx RepositoryContext) []Finding {
	if ctx.BranchProtection.AllowForcePushes == nil || !ctx.BranchProtection.AllowForcePushes.Enabled {
		return nil
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-1", RuleBPForcePush,
		"Default branch allows force pushes",
		fmt.Sprintf(
			"Branch protection on %q permits force pushes. An attacker (or accidental push) can rewrite history, drop reviewed commits, and remove evidence of tampering.",
			ctx.DefaultBranch,
		),
		fmt.Sprintf(
			"Disable \"Allow force pushes\" for %q at %s.",
			ctx.DefaultBranch, settingsURL(ctx, "/settings/branches"),
		),
	)}
}

func checkBranchProtectionDeletion(ctx RepositoryContext) []Finding {
	if ctx.BranchProtection.AllowDeletions == nil || !ctx.BranchProtection.AllowDeletions.Enabled {
		return nil
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-1", RuleBPDeletion,
		"Default branch can be deleted",
		fmt.Sprintf(
			"Branch protection on %q permits deletion. The default branch should never be deletable — losing it destroys history and breaks every downstream consumer.",
			ctx.DefaultBranch,
		),
		fmt.Sprintf(
			"Disable \"Allow deletions\" for %q at %s.",
			ctx.DefaultBranch, settingsURL(ctx, "/settings/branches"),
		),
	)}
}

func checkBranchProtectionNoReview(ctx RepositoryContext) []Finding {
	if ctx.BranchProtection.RequiredPullRequestReviews != nil {
		return nil
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-1", RuleBPNoReview,
		"Default branch does not require pull request reviews",
		fmt.Sprintf(
			"Branch protection on %q exists but does not require a pull request review. Direct pushes still merge code without human approval.",
			ctx.DefaultBranch,
		),
		"Enable \"Require a pull request before merging\" and set the approving review count to at least 1 (2 is recommended for production branches).",
	)}
}

func checkBranchProtectionFewReviewers(ctx RepositoryContext) []Finding {
	r := ctx.BranchProtection.RequiredPullRequestReviews
	if r == nil || r.RequiredApprovingReviewCount >= 2 {
		return nil
	}
	return []Finding{settingFinding(
		SeverityMedium, "CICD-SEC-1", RuleBPFewReviewers,
		"Default branch requires fewer than 2 approving reviews",
		fmt.Sprintf(
			"Branch protection on %q requires only %d approving review(s). A single compromised or coerced reviewer is enough to merge malicious code.",
			ctx.DefaultBranch, r.RequiredApprovingReviewCount,
		),
		"Set \"Required approving reviews\" to 2 or more.",
	)}
}

func checkBranchProtectionStaleReviews(ctx RepositoryContext) []Finding {
	r := ctx.BranchProtection.RequiredPullRequestReviews
	if r == nil || r.DismissStaleReviews {
		return nil
	}
	return []Finding{settingFinding(
		SeverityMedium, "CICD-SEC-1", RuleBPStaleReviews,
		"Default branch does not dismiss stale reviews on new commits",
		"Approvals on a pull request remain valid even after new commits are pushed. An attacker can land a clean review then sneak malicious commits in before merge.",
		"Enable \"Dismiss stale pull request approvals when new commits are pushed\" in the branch protection rule.",
	)}
}

func checkBranchProtectionNoStatusChecks(ctx RepositoryContext) []Finding {
	if ctx.BranchProtection.RequiredStatusChecks != nil {
		return nil
	}
	return []Finding{settingFinding(
		SeverityMedium, "CICD-SEC-1", RuleBPNoStatusChecks,
		"Default branch does not require status checks to pass",
		fmt.Sprintf(
			"Branch protection on %q does not require any status check to pass before merging. Broken builds, failing tests, or unfinished security scans can land on the default branch.",
			ctx.DefaultBranch,
		),
		"Enable \"Require status checks to pass before merging\" and select your CI workflows (typically the GitHub Actions checks Pipefort scans).",
	)}
}

func checkBranchProtectionAdminBypass(ctx RepositoryContext) []Finding {
	if ctx.BranchProtection.EnforceAdmins != nil && ctx.BranchProtection.EnforceAdmins.Enabled {
		return nil
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-1", RuleBPAdminBypass,
		"Admins can bypass branch protection",
		fmt.Sprintf(
			"Branch protection on %q is not enforced for administrators. Any repo admin (or compromised admin token) can push, force-push, or merge without satisfying the rule.",
			ctx.DefaultBranch,
		),
		"Enable \"Do not allow bypassing the above settings\" so the rule applies to everyone, including admins.",
	)}
}

func checkBranchProtectionNoCodeownersReview(ctx RepositoryContext) []Finding {
	if !ctx.HasCodeowners {
		return nil // no CODEOWNERS file = the setting is moot
	}
	r := ctx.BranchProtection.RequiredPullRequestReviews
	if r == nil || r.RequireCodeOwnerReviews {
		return nil
	}
	return []Finding{settingFinding(
		SeverityLow, "CICD-SEC-1", RuleBPNoCodeownersReview,
		"CODEOWNERS exists but their review is not required",
		"This repository defines a CODEOWNERS file, but branch protection does not require their approval. Code owners are declared as the authorities on sensitive paths — without enforcement, that authority is advisory only.",
		"Enable \"Require review from Code Owners\" in the branch protection rule.",
	)}
}

func checkBranchProtectionNoSignedCommits(ctx RepositoryContext) []Finding {
	if ctx.BranchProtection.RequiredSignatures != nil && ctx.BranchProtection.RequiredSignatures.Enabled {
		return nil
	}
	return []Finding{settingFinding(
		SeverityLow, "CICD-SEC-1", RuleBPNoSignedCommits,
		"Default branch does not require signed commits",
		"Commits on the default branch are not required to be GPG/SSH-signed. Without signatures there is no cryptographic proof of who authored a commit (relevant for supply-chain integrity, CICD-SEC-9).",
		"Enable \"Require signed commits\" in the branch protection rule.",
	)}
}

// --- CICD-SEC-4 — workflow permissions ------------------------------------

func checkWorkflowPermissionsWrite(ctx RepositoryContext) []Finding {
	if ctx.WorkflowPerms == nil || ctx.WorkflowPerms.DefaultWorkflowPermissions != "write" {
		return nil
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-4", RuleWPermWrite,
		"Default GITHUB_TOKEN permissions are read-write",
		"The repository's default GITHUB_TOKEN is issued with read AND write permissions to every workflow that does not declare its own `permissions:` block. A malicious or compromised action (or PR with poisoned execution) inherits write access to contents, deployments, packages, and more.",
		fmt.Sprintf(
			"Change the default to read-only at %s → Workflow permissions → \"Read repository contents and packages permissions\". Workflows that need writes should declare them explicitly via `permissions:` (see CICD-SEC-5).",
			settingsURL(ctx, "/settings/actions"),
		),
	)}
}

func checkWorkflowPermissionsPRApprove(ctx RepositoryContext) []Finding {
	if ctx.WorkflowPerms == nil || !ctx.WorkflowPerms.CanApprovePullRequestReviews {
		return nil
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-4", RuleWPermPRApprove,
		"GitHub Actions can approve pull requests",
		"This repository allows GitHub Actions to submit approving reviews on pull requests. Combined with branch protection that counts those reviews, an attacker who controls a workflow can self-approve a malicious PR — fully defeating mandatory code review.",
		fmt.Sprintf(
			"Disable \"Allow GitHub Actions to create and approve pull requests\" at %s → Workflow permissions.",
			settingsURL(ctx, "/settings/actions"),
		),
	)}
}

// --- CICD-SEC-5 — Actions allowlist ---------------------------------------

func checkActionsAllAllowed(ctx RepositoryContext) []Finding {
	if ctx.ActionsPolicy == nil || !ctx.ActionsPolicy.Enabled {
		return nil
	}
	if ctx.ActionsPolicy.AllowedActions != "all" {
		return nil
	}
	return []Finding{settingFinding(
		SeverityMedium, "CICD-SEC-5", RuleActionsAllAllowed,
		"All GitHub Actions and reusable workflows are allowed",
		"The repository's Actions policy permits every action and reusable workflow on the marketplace. Combined with the unpinned-action risk (CICD-SEC-3), this maximises the supply-chain blast radius — any compromised third-party action can execute against this repo.",
		fmt.Sprintf(
			"Switch to \"Allow %s, and select non-%s, actions and reusable workflows\" at %s → Actions permissions, and curate an allowlist of trusted publishers.",
			ctx.Owner, ctx.Owner, settingsURL(ctx, "/settings/actions"),
		),
	)}
}

// --- CICD-SEC-3 — Dependabot ----------------------------------------------

func checkDependabotAlertsOff(ctx RepositoryContext) []Finding {
	if ctx.DependabotAlerts {
		return nil
	}
	return []Finding{settingFinding(
		SeverityMedium, "CICD-SEC-3", RuleDependabotAlertsOff,
		"Dependabot alerts are disabled",
		"This repository is not receiving Dependabot vulnerability alerts. Known-vulnerable dependencies (the root of most CICD-SEC-3 incidents) will not be surfaced.",
		fmt.Sprintf(
			"Enable Dependabot alerts at %s → \"Code security\" → \"Dependabot alerts\".",
			settingsURL(ctx, "/settings/security_analysis"),
		),
	)}
}

func checkDependabotFixesOff(ctx RepositoryContext) []Finding {
	if ctx.Repository == nil || ctx.Repository.SecurityAndAnalysis == nil {
		return nil // status unknown — don't speculate
	}
	s := ctx.Repository.SecurityAndAnalysis.DependabotSecurityUpdates
	if s == nil || s.Status == "enabled" {
		return nil
	}
	return []Finding{settingFinding(
		SeverityLow, "CICD-SEC-3", RuleDependabotFixesOff,
		"Dependabot security updates are disabled",
		"Automated security update PRs are off. Even when an alert fires, a human has to write the bump PR by hand — making it likely to be deferred or forgotten.",
		fmt.Sprintf(
			"Enable Dependabot security updates at %s → \"Code security\".",
			settingsURL(ctx, "/settings/security_analysis"),
		),
	)}
}

// --- CICD-SEC-6 — secret scanning -----------------------------------------

func checkSecretScanningOff(ctx RepositoryContext) []Finding {
	if ctx.Repository == nil || ctx.Repository.SecurityAndAnalysis == nil {
		return nil
	}
	s := ctx.Repository.SecurityAndAnalysis.SecretScanning
	if s == nil || s.Status == "enabled" {
		return nil // not surfaced by GitHub for this repo (private + no GHAS) — skip silently
	}
	return []Finding{settingFinding(
		SeverityMedium, "CICD-SEC-6", RuleSecretScanningOff,
		"Secret scanning is disabled",
		"Secret scanning is available for this repository but turned off. Leaked credentials in commits and pull requests will not be detected (this is the detective control complementing CICD-SEC-6's preventative check for hardcoded secrets).",
		fmt.Sprintf(
			"Enable secret scanning at %s → \"Code security\".",
			settingsURL(ctx, "/settings/security_analysis"),
		),
	)}
}

func checkSecretPushProtectionOff(ctx RepositoryContext) []Finding {
	if ctx.Repository == nil || ctx.Repository.SecurityAndAnalysis == nil {
		return nil
	}
	s := ctx.Repository.SecurityAndAnalysis.SecretScanningPushProtection
	if s == nil || s.Status == "enabled" {
		return nil
	}
	return []Finding{settingFinding(
		SeverityHigh, "CICD-SEC-6", RuleSecretPushProtectionOff,
		"Secret-scanning push protection is disabled",
		"Push protection blocks commits that contain a detected secret before they ever reach the remote. Without it, leaked credentials live in the repo's history (and on every fork/clone) until manually rotated — even after secret scanning flags them.",
		fmt.Sprintf(
			"Enable \"Push protection\" at %s → \"Code security\".",
			settingsURL(ctx, "/settings/security_analysis"),
		),
	)}
}
