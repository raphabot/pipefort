package scanner

// RuleID is the stable, per-check identifier (e.g. "best-prac-2-missing-timeout").
// Finding.Category is the coarser OWASP/best-prac group ("CICD-SEC-1", "BEST-PRAC-2")
// that the existing "owasp" ruleset filter and the auto-fixer dispatch on. We keep
// both: Category preserves backward compatibility with persisted findings and the
// fixer; RuleID gives users a per-check toggle that doesn't accidentally mute
// nine sibling branch-protection rules just because they all share CICD-SEC-1.
type RuleID string

// RuleSurface tells the UI which scan path emits a rule, so the Rule Settings
// page can group "what I check in my workflow YAMLs" apart from "what I check in
// GitHub's repository configuration".
type RuleSurface string

const (
	SurfaceWorkflow     RuleSurface = "workflow"      // produced by ScanBytes
	SurfaceRepoSettings RuleSurface = "repo-settings" // produced by ScanRepositorySettings
)

// Platform names the CI/CD platform a rule targets. Empty defaults to GitHub
// for back-compat with the existing rule catalog — every pre-multi-provider
// rule was implicitly GitHub Actions. New GitLab-specific rules carry
// PlatformGitLab. Portable rules (e.g. best-prac-1-pipe-to-shell,
// cicd-sec-9-download-without-checksum) carry PlatformAny.
type Platform string

const (
	PlatformAny    Platform = ""       // legacy/portable
	PlatformGitHub Platform = "github" // GitHub Actions YAML / repo settings
	PlatformGitLab Platform = "gitlab" // GitLab CI YAML
)

// Workflow checks (ScanBytes) -------------------------------------------------
// Each ID maps to one of the Check* functions in rules.go / slsa_rules.go.
const (
	RulePPECheckout    RuleID = "cicd-sec-1-ppe-checkout"
	RuleLongLivedPAT   RuleID = "cicd-sec-2-long-lived-pat"
	RuleUnpinnedAction RuleID = "cicd-sec-3-unpinned-action"
	RuleUnpinnedImage  RuleID = "cicd-sec-3-unpinned-image"

	// Online pinned-action audits (supplychain_online_rules.go). Opt-in: emitted
	// only by AuditActionPins (CLI --audit-pins / the web scan pipeline), never by
	// the offline ScanBytes pass.
	RuleKnownVulnerableAction RuleID = "cicd-sec-3-known-vulnerable-action"
	RuleImpostorCommit        RuleID = "cicd-sec-3-impostor-commit"
	RuleRefVersionMismatch    RuleID = "cicd-sec-3-ref-version-mismatch"
	RuleTyposquatAction       RuleID = "cicd-sec-3-typosquat-action"
	RuleArchivedAction        RuleID = "cicd-sec-3-archived-action"
	RuleStaleActionRef        RuleID = "cicd-sec-3-stale-action-ref"
	RuleRefConfusion          RuleID = "cicd-sec-3-ref-confusion"
	RulePPEShellInjection     RuleID = "cicd-sec-4-ppe-shell-injection"
	RuleMissingPermissions    RuleID = "cicd-sec-5-missing-permissions"
	RuleHardcodedSecrets      RuleID = "cicd-sec-6-hardcoded-secrets"
	RuleDebugLoggingEnabled   RuleID = "cicd-sec-7-debug-logging-enabled"
	RuleRepoDispatchUnfilt    RuleID = "cicd-sec-8-repository-dispatch-unfiltered"
	RuleDownloadNoChecksum    RuleID = "cicd-sec-9-download-without-checksum"
	RuleContinueOnErrorJob    RuleID = "cicd-sec-10-continue-on-error-job"
	RulePipeToShell           RuleID = "best-prac-1-pipe-to-shell"
	RuleMissingTimeout        RuleID = "best-prac-2-missing-timeout"
	RuleSelfHostedRunners     RuleID = "best-prac-3-self-hosted-runners"

	// Additional workflow checks (rules.go / owasp_extended_rules.go).
	RuleWorkflowRunArtifactPoisoning RuleID = "cicd-sec-1-workflow-run-artifact-poisoning"
	RuleCheckoutPersistCreds         RuleID = "cicd-sec-1-checkout-persist-credentials"
	RuleSecretsInheritPRTarget       RuleID = "cicd-sec-4-secrets-inherit-pr-target"
	RuleSecretInRunOutput            RuleID = "cicd-sec-6-secret-in-run-output"

	// Injection-depth checks (injection_rules.go).
	RuleGitHubEnvInjection      RuleID = "cicd-sec-4-github-env-injection"
	RuleSpoofableActorCondition RuleID = "cicd-sec-1-spoofable-actor-condition"

	// Offline rule-parity batch (condition_rules.go / obfuscation_rules.go /
	// cache_rules.go / publishing_rules.go / concurrency_rules.go /
	// owasp_extended_rules.go).
	RuleUnsoundCondition   RuleID = "cicd-sec-1-unsound-condition"
	RuleUnsoundContains    RuleID = "cicd-sec-1-unsound-contains"
	RuleObfuscatedExpr     RuleID = "cicd-sec-4-obfuscated-expression"
	RuleCachePoisonRelease RuleID = "cicd-sec-4-cache-poisoning-release"
	RuleOverprovSecrets    RuleID = "cicd-sec-6-overprovisioned-secrets"
	RuleUseTrustedPublish  RuleID = "cicd-sec-2-use-trusted-publishing"
	RuleMissingConcurrency RuleID = "best-prac-4-missing-concurrency"

	// Config-driven action allow/deny policy (forbidden_uses.go). Silent unless
	// a .pipefort.yml forbidden-uses block is present.
	RuleForbiddenUses RuleID = "cicd-sec-5-forbidden-uses"

	// SLSA Build-track workflow checks (slsa_rules.go) ------------------------
	RuleSLSAProvenance         RuleID = "slsa-build-l2-provenance"
	RuleSLSAProvenanceIsolated RuleID = "slsa-build-l3-provenance-isolated"
	RuleSLSAOIDCTokenScope     RuleID = "slsa-build-l2-oidc-token-scope"
	RuleSLSAPermsOverlyBroad   RuleID = "slsa-build-l2-perms-overly-broad"
	RuleSLSACachePoisoning     RuleID = "slsa-build-l3-cache-poisoning"
	RuleSLSAVerifyStep         RuleID = "slsa-build-l2-verify-step"

	// GitLab CI workflow checks (gitlab_rules.go) -----------------------------
	// One rule per OWASP CI/CD Top 10 risk that has a portable GitLab analog.
	// IDs follow the `cicd-sec-N-gl-*` convention so the GitHub IDs stay
	// stable. The portable rules (best-prac-1, cicd-sec-9) reuse their
	// existing IDs across both platforms — there is no `-gl-` parallel.
	RuleGitLabMRTarget          RuleID = "cicd-sec-1-gl-mr-target"
	RuleGitLabPATSecret         RuleID = "cicd-sec-2-gl-pat-secret"
	RuleGitLabUnpinnedInclude   RuleID = "cicd-sec-3-gl-unpinned-include"
	RuleGitLabShellInjection    RuleID = "cicd-sec-4-gl-shell-injection"
	RuleGitLabHardcodedSecrets  RuleID = "cicd-sec-6-gl-hardcoded-secrets"
	RuleGitLabDebugTrace        RuleID = "cicd-sec-7-gl-debug-trace"
	RuleGitLabTriggerUnfiltered RuleID = "cicd-sec-8-gl-trigger-unfiltered"
	RuleGitLabAllowFailure      RuleID = "cicd-sec-10-gl-allow-failure"
	RuleGitLabMissingTimeout    RuleID = "best-prac-2-gl-missing-timeout"
	RuleGitLabSelfHostedTags    RuleID = "best-prac-3-gl-self-hosted-tags"
	RuleGitLabMissingResGroup   RuleID = "best-prac-4-gl-missing-resource-group"

	// GitLab project-settings checks (settings_gitlab.go, Surface repo-settings).
	RuleGitLabBPMissing       RuleID = "cicd-sec-1-gl-bp-missing"
	RuleGitLabBPForcePush     RuleID = "cicd-sec-1-gl-bp-force-push"
	RuleGitLabMergeNoPipeline RuleID = "cicd-sec-1-gl-merge-without-pipeline"
	RuleGitLabNoApprovals     RuleID = "cicd-sec-1-gl-no-approvals"
	RuleGitLabPublicPipelines RuleID = "cicd-sec-4-gl-public-pipelines"
)

// Repository-settings checks (ScanRepositorySettings) ------------------------
// Each ID maps to one of the helper functions in settings.go. The slugs match
// the existing docs/rules/<slug>.mdx pages so doc URLs are derivable.
const (
	RuleBPMissing            RuleID = "cicd-sec-1-bp-missing"
	RuleBPForcePush          RuleID = "cicd-sec-1-bp-force-push"
	RuleBPDeletion           RuleID = "cicd-sec-1-bp-deletion"
	RuleBPNoReview           RuleID = "cicd-sec-1-bp-no-review"
	RuleBPFewReviewers       RuleID = "cicd-sec-1-bp-few-reviewers"
	RuleBPStaleReviews       RuleID = "cicd-sec-1-bp-stale-reviews"
	RuleBPNoStatusChecks     RuleID = "cicd-sec-1-bp-no-status-checks"
	RuleBPAdminBypass        RuleID = "cicd-sec-1-bp-admin-bypass"
	RuleBPNoCodeownersReview RuleID = "cicd-sec-1-bp-no-codeowners-review"
	RuleBPNoSignedCommits    RuleID = "cicd-sec-1-bp-no-signed-commits"

	RuleWPermWrite     RuleID = "cicd-sec-4-wperm-write"
	RuleWPermPRApprove RuleID = "cicd-sec-4-wperm-pr-approve"

	RuleActionsAllAllowed RuleID = "cicd-sec-5-actions-all-allowed"

	RuleDependabotAlertsOff RuleID = "cicd-sec-3-dependabot-alerts-off"
	RuleDependabotFixesOff  RuleID = "cicd-sec-3-dependabot-fixes-off"

	RuleSecretScanningOff       RuleID = "cicd-sec-6-secret-scanning-off"
	RuleSecretPushProtectionOff RuleID = "cicd-sec-6-secret-push-protection-off"
)

// Framework labels grouping rules into compliance/security frameworks. A rule
// can belong to multiple frameworks at once (e.g. action-pinning is both an
// OWASP check and a SLSA Build L3 prerequisite). The CLI's --ruleset flag and
// the web app's ruleset selector accept these as filter values directly, plus
// the umbrella "slsa" alias that matches any "slsa-*" entry.
//
// SLSA labels track the SLSA v1.2 specification (https://slsa.dev/spec/v1.2/).
// The Build track levels (L1/L2/L3) are unchanged from v1.0; the Source track
// (L1 Version Controlled → L2 History & Provenance → L3 Continuous Technical
// Controls → L4 Two-Party Review) is new/promoted-from-draft in v1.2.
const (
	FrameworkOWASP        = "owasp"
	FrameworkSLSABuildL1  = "slsa-build-l1"
	FrameworkSLSABuildL2  = "slsa-build-l2"
	FrameworkSLSABuildL3  = "slsa-build-l3"
	FrameworkSLSASourceL1 = "slsa-source-l1" // version controlled (trivially satisfied for any GitHub repo)
	FrameworkSLSASourceL2 = "slsa-source-l2" // preserve change history (immutable refs, tag protection)
	FrameworkSLSASourceL3 = "slsa-source-l3" // continuous technical controls (branch protection, status checks)
	FrameworkSLSASourceL4 = "slsa-source-l4" // two-party review
)

// Persona groups rules by signal-to-noise, zizmor-style. The CLI's --persona
// flag admits rules at or below the selected tier: `regular` (the default)
// keeps only high-signal security checks, `pedantic` adds hygiene/best-practice
// nits, and `auditor` adds everything — including checks that surface things
// worth a look but rarely actionable on their own.
type Persona string

const (
	PersonaRegular  Persona = "regular"
	PersonaPedantic Persona = "pedantic"
	PersonaAuditor  Persona = "auditor"
)

// personaRank orders personas for filtering. Unknown values rank as regular.
func personaRank(p Persona) int {
	switch p {
	case PersonaAuditor:
		return 3
	case PersonaPedantic:
		return 2
	default:
		return 1
	}
}

// RuleSpec describes a single user-toggleable check. The web app reads this
// catalog over GET /api/rules to render the Rule Settings page; the Go API
// uses it on PUT to validate that a rule_id submitted by the client is real.
type RuleSpec struct {
	ID              RuleID      `json:"id"`
	Category        string      `json:"category"` // "CICD-SEC-1", "BEST-PRAC-2", ...
	Title           string      `json:"title"`
	DefaultSeverity Severity    `json:"default_severity"`
	Surface         RuleSurface `json:"surface"`
	Platform        Platform    `json:"platform,omitempty"` // empty = github (legacy default)
	Description     string      `json:"description"`
	DocURL          string      `json:"doc_url"` // "/rules/<id>"
	// Frameworks the rule serves. A rule with no frameworks is unfiltered (it
	// only shows up under the "all" ruleset). Use the Framework* constants.
	Frameworks []string `json:"frameworks"`
	// DefaultConfidence is stamped onto findings that don't carry their own.
	// Left empty in the catalog literal it normalizes to ConfidenceHigh —
	// only heuristic rules need an explicit entry.
	DefaultConfidence Confidence `json:"default_confidence"`
	// Persona tiers the rule for noise filtering. Empty normalizes to
	// PersonaRegular — only pedantic/auditor rules need an explicit entry.
	Persona Persona `json:"persona"`
}

// Rules returns the canonical catalog in the order pages should render. New
// scanner checks must add an entry here (and a docs/rules/<id>.mdx page —
// see CLAUDE.md convention 3) so users can toggle them.
//
// Entries may leave DefaultConfidence/Persona empty; Rules() normalizes those
// to ConfidenceHigh/PersonaRegular so consumers never see a zero value.
func Rules() []RuleSpec {
	specs := ruleCatalog()
	for i := range specs {
		if specs[i].DefaultConfidence == "" {
			specs[i].DefaultConfidence = ConfidenceHigh
		}
		if specs[i].Persona == "" {
			specs[i].Persona = PersonaRegular
		}
	}
	return specs
}

func ruleCatalog() []RuleSpec {
	return []RuleSpec{
		// --- Workflow YAML checks ----------------------------------------
		{
			ID:              RulePPECheckout,
			Category:        "CICD-SEC-1",
			Title:           "Dangerous checkout in pull_request_target workflow",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Detects pull_request_target workflows that check out the PR head ref and then run untrusted code with repository secrets.",
			DocURL:          "/rules/cicd-sec-1",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL3},
		},
		{
			ID:                RuleLongLivedPAT,
			Category:          "CICD-SEC-2",
			Title:             "Long-lived personal access token used in workflow",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags workflows authenticating with secrets whose names indicate a long-lived personal access token (e.g. *_PAT, *_PERSONAL_ACCESS_TOKEN) instead of the short-lived GITHUB_TOKEN or OIDC federation.",
			DocURL:            "/rules/cicd-sec-2",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleUnpinnedAction,
			Category:        "CICD-SEC-3",
			Title:           "Unpinned third-party action",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "Flags actions referenced by tag or branch instead of a full commit SHA, which are mutable and a supply-chain risk.",
			DocURL:          "/rules/cicd-sec-3",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL3},
		},
		{
			ID:              RuleUnpinnedImage,
			Category:        "CICD-SEC-3",
			Title:           "Unpinned container image",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "Flags job containers, service containers, and docker:// step images referenced by a mutable tag instead of an immutable @sha256: digest.",
			DocURL:          "/rules/cicd-sec-3-unpinned-image",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL3},
		},
		{
			ID:              RuleKnownVulnerableAction,
			Category:        "CICD-SEC-3",
			Title:           "Known-vulnerable action version",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags a pinned action whose version falls in a published GitHub Security Advisory (GHSA) vulnerable range. Requires the opt-in --audit-pins online pass.",
			DocURL:          "/rules/cicd-sec-3-known-vulnerable-action",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleImpostorCommit,
			Category:        "CICD-SEC-3",
			Title:           "Impostor commit pin",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags an action pinned to a commit SHA that does not exist in the claimed upstream repository (it may belong to a fork). Requires the opt-in --audit-pins online pass.",
			DocURL:          "/rules/cicd-sec-3-impostor-commit",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL3},
		},
		{
			ID:              RuleRefVersionMismatch,
			Category:        "CICD-SEC-3",
			Title:           "Pinned SHA does not match its version comment",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "Flags an action pinned to a commit SHA whose trailing version comment (e.g. # v3) names a tag that resolves to a different commit. Requires the opt-in --audit-pins online pass.",
			DocURL:          "/rules/cicd-sec-3-ref-version-mismatch",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleTyposquatAction,
			Category:          "CICD-SEC-3",
			Title:             "Possible typosquatted action",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags an action whose owner/repo is one character away from a popular action. Requires the opt-in --audit-pins pass.",
			DocURL:            "/rules/cicd-sec-3-typosquat-action",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleArchivedAction,
			Category:        "CICD-SEC-3",
			Title:           "Action's upstream repository is archived",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags a `uses:` reference to a repository GitHub reports as archived (read-only, unmaintained). Archived actions receive no security fixes. Runs in the online pass.",
			DocURL:          "/rules/cicd-sec-3-archived-action",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL3},
		},
		{
			ID:                RuleStaleActionRef,
			Category:          "CICD-SEC-3",
			Title:             "Pinned SHA is not any released tag",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags an action pinned to a commit SHA that is not the tip of any tag upstream — i.e. pinned to unreleased or arbitrary code rather than a published release. Runs in the online pass.",
			DocURL:            "/rules/cicd-sec-3-stale-action-ref",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
			Persona:           PersonaAuditor,
		},
		{
			ID:              RuleRefConfusion,
			Category:        "CICD-SEC-3",
			Title:           "Action ref exists as both a branch and a tag",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags a `uses:` ref that resolves ambiguously upstream — the same name exists as both a branch and a tag. GitHub's resolution order is exploitable, so an attacker who controls the branch can shadow the intended tag. Runs in the online pass.",
			DocURL:          "/rules/cicd-sec-3-ref-confusion",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL3},
		},
		{
			ID:              RulePPEShellInjection,
			Category:        "CICD-SEC-4",
			Title:           "Poisoned pipeline execution (shell injection)",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Detects inline scripts that interpolate untrusted github.event data directly into the shell.",
			DocURL:          "/rules/cicd-sec-4",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleMissingPermissions,
			Category:        "CICD-SEC-5",
			Title:           "Missing permissions specification",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "Flags workflows that omit an explicit permissions block and inherit overly broad defaults.",
			DocURL:          "/rules/cicd-sec-5",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL2},
		},
		{
			ID:                RuleHardcodedSecrets,
			Category:          "CICD-SEC-6",
			Title:             "Hardcoded secrets in workflow",
			DefaultSeverity:   SeverityHigh,
			Surface:           SurfaceWorkflow,
			Description:       "Detects credentials embedded in env: blocks or inline scripts (PATs, AWS keys, Slack tokens, suspicious env-var names).",
			DocURL:            "/rules/cicd-sec-6",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleDebugLoggingEnabled,
			Category:        "CICD-SEC-7",
			Title:           "Actions debug logging enabled in workflow",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags workflows that set ACTIONS_STEP_DEBUG or ACTIONS_RUNNER_DEBUG to a truthy value in env. Debug logs include unmasked environment values and can leak secrets to anyone with read access to workflow logs.",
			DocURL:          "/rules/cicd-sec-7",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleRepoDispatchUnfilt,
			Category:        "CICD-SEC-8",
			Title:           "repository_dispatch trigger without event-type allowlist",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "Flags workflows triggered by repository_dispatch without an explicit types: allowlist. Any third-party service holding a token with repo scope can dispatch arbitrary event types and trigger the workflow with attacker-controlled inputs.",
			DocURL:          "/rules/cicd-sec-8",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleDownloadNoChecksum,
			Category:          "CICD-SEC-9",
			Title:             "Downloaded artifact has no integrity check",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags inline scripts that fetch an archive or binary via curl/wget without a matching checksum, signature, or attestation verification in the same step.",
			DocURL:            "/rules/cicd-sec-9",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleContinueOnErrorJob,
			Category:        "CICD-SEC-10",
			Title:           "Job-level continue-on-error suppresses failure visibility",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Description:     "Flags jobs that declare continue-on-error: true at the job level. The job's failure is reported as a success, so required-check gates and audit dashboards never see it.",
			DocURL:          "/rules/cicd-sec-10",
			Frameworks:      []string{FrameworkOWASP},
			Persona:         PersonaPedantic,
		},
		{
			ID:              RulePipeToShell,
			Category:        "BEST-PRAC-1",
			Title:           "Command piped directly to shell",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Detects curl/wget output piped straight into sh/bash/zsh/ksh, which executes whatever the server returned at that moment.",
			DocURL:          "/rules/best-prac-1",
			Frameworks:      []string{FrameworkSLSABuildL1},
		},
		{
			ID:              RuleMissingTimeout,
			Category:        "BEST-PRAC-2",
			Title:           "Job timeout not configured",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Description:     "Flags jobs that omit timeout-minutes and inherit the 6-hour default.",
			DocURL:          "/rules/best-prac-2",
			Persona:         PersonaPedantic,
		},
		{
			ID:              RuleSelfHostedRunners,
			Category:        "BEST-PRAC-3",
			Title:           "Self-hosted runner usage",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Description:     "Flags jobs targeting self-hosted runners, which may bridge to internal infrastructure.",
			DocURL:          "/rules/best-prac-3",
			Frameworks:      []string{FrameworkSLSABuildL2},
			Persona:         PersonaAuditor,
		},
		{
			ID:              RuleWorkflowRunArtifactPoisoning,
			Category:        "CICD-SEC-1",
			Title:           "workflow_run downloads artifacts from the triggering run",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags workflow_run workflows that download artifacts produced by the (untrusted) triggering run and then use them. A fork PR can upload a poisoned artifact that the privileged workflow_run trusts, leading to code execution or content injection in the base context.",
			DocURL:          "/rules/cicd-sec-1-workflow-run-artifact-poisoning",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleCheckoutPersistCreds,
			Category:        "CICD-SEC-1",
			Title:           "Checkout persists credentials under a privileged trigger",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "In a pull_request_target/workflow_run workflow, an actions/checkout step does not set persist-credentials: false, leaving the job's token in .git/config where later untrusted steps can read it.",
			DocURL:          "/rules/cicd-sec-1-checkout-persist-credentials",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleSecretsInheritPRTarget,
			Category:        "CICD-SEC-4",
			Title:           "Reusable workflow called with secrets: inherit under a privileged trigger",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "In a pull_request_target/workflow_run workflow, a job calls a reusable workflow with secrets: inherit, handing the full set of repository secrets to a called workflow that runs in an attacker-influenced context.",
			DocURL:          "/rules/cicd-sec-4-secrets-inherit-pr-target",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleSecretInRunOutput,
			Category:          "CICD-SEC-6",
			Title:             "Secret printed to logs or written to step output",
			DefaultSeverity:   SeverityHigh,
			Surface:           SurfaceWorkflow,
			Description:       "Flags inline scripts that echo/print a ${{ secrets.* }} value or write it to $GITHUB_OUTPUT/$GITHUB_ENV/::set-output, defeating GitHub's log masking and persisting the secret where later steps and log readers can see it.",
			DocURL:            "/rules/cicd-sec-6-secret-in-run-output",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleGitHubEnvInjection,
			Category:        "CICD-SEC-4",
			Title:           "Untrusted input written to GITHUB_ENV/GITHUB_PATH",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Detects writes to $GITHUB_ENV or $GITHUB_PATH whose value derives from untrusted event data — directly or laundered through an env: var — poisoning the environment and PATH of every later step.",
			DocURL:          "/rules/cicd-sec-4-github-env-injection",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleSpoofableActorCondition,
			Category:          "CICD-SEC-1",
			Title:             "Security decision based on a spoofable actor check",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags an if: gate that authorizes privileged logic based solely on a github.actor / github.triggering_actor comparison to a bot login, which is spoofable in several trigger contexts.",
			DocURL:            "/rules/cicd-sec-1-spoofable-actor-condition",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},

		// --- Offline rule-parity batch -----------------------------------
		{
			ID:              RuleUnsoundCondition,
			Category:        "CICD-SEC-1",
			Title:           "Job/step condition is always true",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags an if: whose GitHub expression is wrapped in a quoted string, so it evaluates to a non-empty (always-truthy) literal instead of a boolean — the guard it looks like it enforces never actually gates anything.",
			DocURL:          "/rules/cicd-sec-1-unsound-condition",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleUnsoundContains,
			Category:          "CICD-SEC-1",
			Title:             "Spoofable contains() membership check",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags contains('a b c', github.ref)-style checks where a string haystack is tested for an attacker-influenceable needle: a crafted ref/label can satisfy the substring match and pass the gate.",
			DocURL:            "/rules/cicd-sec-1-unsound-contains",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
			Persona:           PersonaPedantic,
		},
		{
			ID:                RuleObfuscatedExpr,
			Category:          "CICD-SEC-4",
			Title:             "Obfuscated expression or run script",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags obfuscation that hides untrusted-input flow from review: index-notation context access (github['event']['…']), and base64-decode-and-execute in run scripts.",
			DocURL:            "/rules/cicd-sec-4-obfuscated-expression",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
			Persona:           PersonaPedantic,
		},
		{
			ID:                RuleCachePoisonRelease,
			Category:          "CICD-SEC-4",
			Title:             "Caching enabled in a publishing workflow",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Description:       "Flags dependency caching (actions/cache or a setup-* action's cache option) in a workflow that also publishes a release-shaped artifact: a poisoned cache entry from a less-trusted workflow can flow into the published output.",
			DocURL:            "/rules/cicd-sec-4-cache-poisoning-release",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleOverprovSecrets,
			Category:        "CICD-SEC-6",
			Title:           "Secrets over-provisioned to the whole workflow",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags ${{ toJSON(secrets) }} (exposes every secret at once) and workflow-level env: mappings of secrets.* (which leak into every step of every job rather than the one step that needs them).",
			DocURL:          "/rules/cicd-sec-6-overprovisioned-secrets",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleUseTrustedPublish,
			Category:        "CICD-SEC-2",
			Title:           "Package published with a long-lived token instead of OIDC",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "Flags a publishing step that authenticates with a long-lived registry token (PyPI/npm/cargo/rubygems) where the registry supports OIDC trusted publishing — short-lived, per-run credentials that remove the standing secret.",
			DocURL:          "/rules/cicd-sec-2-use-trusted-publishing",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleMissingConcurrency,
			Category:        "BEST-PRAC-4",
			Title:           "Deploy/release workflow has no concurrency guard",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Description:     "Flags deploy/release-shaped workflows without a concurrency: group. Overlapping runs can race on shared caches, artifacts, and deploy targets, producing double-deploys or inconsistent state.",
			DocURL:          "/rules/best-prac-4-missing-concurrency",
			Persona:         PersonaPedantic,
		},
		{
			ID:              RuleForbiddenUses,
			Category:        "CICD-SEC-5",
			Title:           "Action not permitted by forbidden-uses policy",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "Flags a `uses:` reference that violates the repository's forbidden-uses policy in .pipefort.yml (an allow list it is not on, or a deny list it matches). Silent when no policy is configured.",
			DocURL:          "/rules/cicd-sec-5-forbidden-uses",
			Frameworks:      []string{FrameworkOWASP},
		},

		// --- SLSA Build-track workflow checks ----------------------------
		{
			ID:                RuleSLSAProvenance,
			Category:          "SLSA-BUILD-L2",
			Title:             "Build provenance is not generated",
			DefaultSeverity:   SeverityHigh,
			Surface:           SurfaceWorkflow,
			Description:       "A workflow that publishes a release-shaped artifact (release upload, container push, …) does not generate a SLSA build provenance attestation. Required for SLSA v1.2 Build L2 (Hosted build platform with signed provenance).",
			DocURL:            "/rules/slsa-build-l2-provenance",
			Frameworks:        []string{FrameworkSLSABuildL2},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleSLSAProvenanceIsolated,
			Category:        "SLSA-BUILD-L3",
			Title:           "Provenance is generated in the same job as the build (not isolated)",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "In-job attestation steps (actions/attest-build-provenance) satisfy SLSA v1.2 Build L2 but not L3 — the user's run steps share the job's signing context. SLSA v1.2 Build L3 (Hardened builds) requires the slsa-framework/slsa-github-generator reusable workflow.",
			DocURL:          "/rules/slsa-build-l3-provenance-isolated",
			Frameworks:      []string{FrameworkSLSABuildL3},
		},
		{
			ID:              RuleSLSAOIDCTokenScope,
			Category:        "SLSA-BUILD-L2",
			Title:           "Provenance/signing step is missing id-token: write permission",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Description:     "A job using actions/attest*, sigstore/cosign, or slsa-github-generator must declare permissions.id-token: write on the job to mint the OIDC token Sigstore needs for keyless signing. Required for SLSA v1.2 Build L2.",
			DocURL:          "/rules/slsa-build-l2-oidc-token-scope",
			Frameworks:      []string{FrameworkSLSABuildL2},
		},
		{
			ID:              RuleSLSAPermsOverlyBroad,
			Category:        "SLSA-BUILD-L2",
			Title:           "Permissions block grants overly broad scopes",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "An explicit permissions block declares write-all (or write to every scope), which defeats the point of declaring permissions. SLSA v1.2 Build L2 hardening expects least privilege.",
			DocURL:          "/rules/slsa-build-l2-perms-overly-broad",
			Frameworks:      []string{FrameworkSLSABuildL2},
		},
		{
			ID:              RuleSLSACachePoisoning,
			Category:        "SLSA-BUILD-L3",
			Title:           "Cache key in pull_request_target derived from PR-controlled input",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Description:     "In a pull_request_target workflow, an actions/cache key interpolates a PR-controlled context (github.head_ref, pull_request head metadata). An attacker can poison the cache for the base branch — violating SLSA v1.2 Build L3 isolation.",
			DocURL:          "/rules/slsa-build-l3-cache-poisoning",
			Frameworks:      []string{FrameworkSLSABuildL3},
		},
		{
			ID:              RuleSLSAVerifyStep,
			Category:        "SLSA-BUILD-L2",
			Title:           "Workflow consumes artifacts but does not verify provenance",
			DefaultSeverity: SeverityInfo,
			Surface:         SurfaceWorkflow,
			Description:     "Workflows that download artifacts or pull container images should verify provenance (gh attestation verify / slsa-verifier / cosign verify-attestation) before using them — otherwise the consumer side of SLSA v1.2 Build L2 is missing.",
			DocURL:          "/rules/slsa-build-l2-verify-step",
			Frameworks:      []string{FrameworkSLSABuildL2},
		},

		// --- GitLab CI workflow checks -----------------------------------
		{
			ID:              RuleGitLabMRTarget,
			Category:        "CICD-SEC-1",
			Title:           "GitLab job runs untrusted MR code with pipeline secrets",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Detects jobs that run on merge_request_event and explicitly check out the MR source branch in `script`, exposing pipeline CI variables to attacker-controlled code.",
			DocURL:          "/rules/cicd-sec-1-gl-mr-target",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleGitLabPATSecret,
			Category:          "CICD-SEC-2",
			Title:             "GitLab job uses a long-lived access token",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceWorkflow,
			Platform:          PlatformGitLab,
			Description:       "Flags CI variables whose names match the shape of a long-lived personal/group access token instead of the short-lived $CI_JOB_TOKEN.",
			DocURL:            "/rules/cicd-sec-2-gl-pat-secret",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleGitLabUnpinnedInclude,
			Category:        "CICD-SEC-3",
			Title:           "GitLab include without pinned ref",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Flags `include:` of remote URLs or `include: project:` entries without a SHA-pinned `ref:` — supply-chain risk if the upstream template changes.",
			DocURL:          "/rules/cicd-sec-3-gl-unpinned-include",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleGitLabShellInjection,
			Category:        "CICD-SEC-4",
			Title:           "GitLab poisoned pipeline execution (shell injection)",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Detects scripts that interpolate attacker-controlled $CI_MERGE_REQUEST_* / $CI_COMMIT_* metadata directly into the shell.",
			DocURL:          "/rules/cicd-sec-4-gl-shell-injection",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleGitLabHardcodedSecrets,
			Category:          "CICD-SEC-6",
			Title:             "Hardcoded secrets in GitLab CI variables",
			DefaultSeverity:   SeverityHigh,
			Surface:           SurfaceWorkflow,
			Platform:          PlatformGitLab,
			Description:       "Detects literal credentials embedded in `variables:` (top-level or per-job) — AWS keys, Slack tokens, GitHub/GitLab PATs.",
			DocURL:            "/rules/cicd-sec-6-gl-hardcoded-secrets",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleGitLabDebugTrace,
			Category:        "CICD-SEC-7",
			Title:           "GitLab pipeline debug logging enabled",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Flags `CI_DEBUG_TRACE`/`CI_DEBUG_SERVICES` set to a truthy value in `variables:`. Debug logs expand masked CI variables and can leak secrets to anyone with Reporter access.",
			DocURL:          "/rules/cicd-sec-7-gl-debug-trace",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleGitLabTriggerUnfiltered,
			Category:        "CICD-SEC-8",
			Title:           "GitLab trigger pipeline accepted from any source",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Flags jobs that run on external trigger or upstream-pipeline events without restricting the upstream project or branch via `rules:`.",
			DocURL:          "/rules/cicd-sec-8-gl-trigger-unfiltered",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleGitLabAllowFailure,
			Category:        "CICD-SEC-10",
			Title:           "GitLab job declares allow_failure: true",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Pipeline status reports success even if the job fails — required-status gates and audit dashboards never see it.",
			DocURL:          "/rules/cicd-sec-10-gl-allow-failure",
			Frameworks:      []string{FrameworkOWASP},
			Persona:         PersonaPedantic,
		},
		{
			ID:              RuleGitLabMissingTimeout,
			Category:        "BEST-PRAC-2",
			Title:           "GitLab job has no timeout configured",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Flags jobs without `timeout:` that don't inherit one from `default: { timeout: ... }`.",
			DocURL:          "/rules/best-prac-2-gl-missing-timeout",
			Persona:         PersonaPedantic,
		},
		{
			ID:              RuleGitLabSelfHostedTags,
			Category:        "BEST-PRAC-3",
			Title:           "GitLab job targets a self-hosted runner",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Flags jobs whose `tags:` target a non-SaaS-shared runner (i.e. a self-hosted or project-specific runner).",
			DocURL:          "/rules/best-prac-3-gl-self-hosted-tags",
			Persona:         PersonaAuditor,
		},
		{
			ID:              RuleGitLabMissingResGroup,
			Category:        "BEST-PRAC-4",
			Title:           "GitLab deploy job has no resource_group",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceWorkflow,
			Platform:        PlatformGitLab,
			Description:     "Flags jobs with an `environment:` (a deployment) that declare no `resource_group:`. Concurrent pipelines can then deploy to the same environment simultaneously, racing on the target.",
			DocURL:          "/rules/best-prac-4-gl-missing-resource-group",
			Persona:         PersonaPedantic,
		},

		// --- GitLab project settings (CICD-SEC-1 / 4) --------------------
		{
			ID:              RuleGitLabBPMissing,
			Category:        "CICD-SEC-1",
			Title:           "GitLab default branch is not protected",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Platform:        PlatformGitLab,
			Description:     "The project's default branch has no Protected Branch entry, so anyone with push access can commit directly and rewrite history.",
			DocURL:          "/rules/cicd-sec-1-gl-bp-missing",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleGitLabBPForcePush,
			Category:        "CICD-SEC-1",
			Title:           "GitLab protected default branch allows force push",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Platform:        PlatformGitLab,
			Description:     "The protected default branch permits force pushes, allowing history rewrites that erase the record of what was merged.",
			DocURL:          "/rules/cicd-sec-1-gl-bp-force-push",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleGitLabMergeNoPipeline,
			Category:        "CICD-SEC-1",
			Title:           "GitLab merges allowed without a passing pipeline",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Platform:        PlatformGitLab,
			Description:     "`only_allow_merge_if_pipeline_succeeds` is off, so merge requests can merge even when CI (including security checks) fails.",
			DocURL:          "/rules/cicd-sec-1-gl-merge-without-pipeline",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:                RuleGitLabNoApprovals,
			Category:          "CICD-SEC-1",
			Title:             "GitLab merge requests require no approvals",
			DefaultSeverity:   SeverityMedium,
			Surface:           SurfaceRepoSettings,
			Platform:          PlatformGitLab,
			Description:       "The project requires zero approvals before merge, so a single actor can merge unreviewed changes. (Premium-tier setting; skipped when unavailable.)",
			DocURL:            "/rules/cicd-sec-1-gl-no-approvals",
			Frameworks:        []string{FrameworkOWASP},
			DefaultConfidence: ConfidenceMedium,
		},
		{
			ID:              RuleGitLabPublicPipelines,
			Category:        "CICD-SEC-4",
			Title:           "GitLab public pipelines expose job logs and artifacts",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Platform:        PlatformGitLab,
			Description:     "Public pipelines (`public_builds`) let non-members view CI job logs and download artifacts, which can leak secrets echoed in logs or build outputs.",
			DocURL:          "/rules/cicd-sec-4-gl-public-pipelines",
			Frameworks:      []string{FrameworkOWASP},
		},

		// --- Branch protection (CICD-SEC-1) ------------------------------
		{
			ID:              RuleBPMissing,
			Category:        "CICD-SEC-1",
			Title:           "Default branch has no branch protection rule",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "The default branch has no protection — anyone with write access can push directly, force-push, or delete it. SLSA v1.2 Source L3 requires continuous technical controls on protected Named References.",
			DocURL:          "/rules/cicd-sec-1-bp-missing",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL3},
		},
		{
			ID:              RuleBPForcePush,
			Category:        "CICD-SEC-1",
			Title:           "Default branch allows force pushes",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "Branch protection permits force pushes, letting an attacker rewrite history and drop reviewed commits. SLSA v1.2 Source L2 requires immutable change history.",
			DocURL:          "/rules/cicd-sec-1-bp-force-push",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL2},
		},
		{
			ID:              RuleBPDeletion,
			Category:        "CICD-SEC-1",
			Title:           "Default branch can be deleted",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "Branch protection permits deletion of the default branch. SLSA v1.2 Source L2 requires preserving change history.",
			DocURL:          "/rules/cicd-sec-1-bp-deletion",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL2},
		},
		{
			ID:              RuleBPNoReview,
			Category:        "CICD-SEC-1",
			Title:           "Default branch does not require pull request reviews",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "Branch protection exists but does not require a pull request review. SLSA v1.2 Source L4 requires two-party review before merging.",
			DocURL:          "/rules/cicd-sec-1-bp-no-review",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL4},
		},
		{
			ID:              RuleBPFewReviewers,
			Category:        "CICD-SEC-1",
			Title:           "Default branch requires fewer than 2 approving reviews",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Description:     "A single compromised or coerced reviewer is enough to merge malicious code. SLSA v1.2 Source L4 requires two trusted persons prior to submission.",
			DocURL:          "/rules/cicd-sec-1-bp-few-reviewers",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL4},
		},
		{
			ID:              RuleBPStaleReviews,
			Category:        "CICD-SEC-1",
			Title:           "Default branch does not dismiss stale reviews on new commits",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Description:     "Approvals stay valid after new commits are pushed, enabling sneak-in attacks. SLSA v1.2 Source L4 requires reviewing the actual code that will be merged.",
			DocURL:          "/rules/cicd-sec-1-bp-stale-reviews",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL4},
		},
		{
			ID:              RuleBPNoStatusChecks,
			Category:        "CICD-SEC-1",
			Title:           "Default branch does not require status checks to pass",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Description:     "Broken builds, failing tests, or unfinished scans can land on the default branch. SLSA v1.2 Source L3 expects technical controls to gate merges.",
			DocURL:          "/rules/cicd-sec-1-bp-no-status-checks",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL3},
		},
		{
			ID:              RuleBPAdminBypass,
			Category:        "CICD-SEC-1",
			Title:           "Admins can bypass branch protection",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "Branch protection is not enforced for administrators — any admin (or compromised admin token) bypasses it. SLSA v1.2 Source L3 requires controls that cannot be unilaterally bypassed.",
			DocURL:          "/rules/cicd-sec-1-bp-admin-bypass",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL3},
		},
		{
			ID:              RuleBPNoCodeownersReview,
			Category:        "CICD-SEC-1",
			Title:           "CODEOWNERS exists but their review is not required",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceRepoSettings,
			Description:     "A CODEOWNERS file is declared but branch protection does not require code-owner approvals. SLSA v1.2 Source L4 expects review by trusted persons (often expressed via CODEOWNERS).",
			DocURL:          "/rules/cicd-sec-1-bp-no-codeowners-review",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL4},
		},
		{
			ID:              RuleBPNoSignedCommits,
			Category:        "CICD-SEC-1",
			Title:           "Default branch does not require signed commits",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceRepoSettings,
			Description:     "Commits are not required to be GPG/SSH signed, weakening commit-author authenticity. Signed commits strengthen identity attestation under SLSA v1.2 Source L2.",
			DocURL:          "/rules/cicd-sec-1-bp-no-signed-commits",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL2},
		},

		// --- Workflow permissions (CICD-SEC-4) ---------------------------
		{
			ID:              RuleWPermWrite,
			Category:        "CICD-SEC-4",
			Title:           "Default GITHUB_TOKEN permissions are read-write",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "The repo issues a read+write GITHUB_TOKEN by default to workflows that don't declare their own permissions.",
			DocURL:          "/rules/cicd-sec-4-wperm-write",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL2},
		},
		{
			ID:              RuleWPermPRApprove,
			Category:        "CICD-SEC-4",
			Title:           "GitHub Actions can approve pull requests",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "Allows workflows to submit approving reviews — fully defeating mandatory code review. SLSA v1.2 Source L4 requires two trusted human persons, not an automated bot, to satisfy the review requirement.",
			DocURL:          "/rules/cicd-sec-4-wperm-pr-approve",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSASourceL4},
		},

		// --- Actions allowlist (CICD-SEC-5) ------------------------------
		{
			ID:              RuleActionsAllAllowed,
			Category:        "CICD-SEC-5",
			Title:           "All GitHub Actions and reusable workflows are allowed",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Description:     "Every marketplace action is permitted, maximising the supply-chain blast radius.",
			DocURL:          "/rules/cicd-sec-5-actions-all-allowed",
			Frameworks:      []string{FrameworkOWASP, FrameworkSLSABuildL3},
		},

		// --- Dependabot (CICD-SEC-3) -------------------------------------
		{
			ID:              RuleDependabotAlertsOff,
			Category:        "CICD-SEC-3",
			Title:           "Dependabot alerts are disabled",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Description:     "Known-vulnerable dependencies will not be surfaced for this repository.",
			DocURL:          "/rules/cicd-sec-3-dependabot-alerts-off",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleDependabotFixesOff,
			Category:        "CICD-SEC-3",
			Title:           "Dependabot security updates are disabled",
			DefaultSeverity: SeverityLow,
			Surface:         SurfaceRepoSettings,
			Description:     "Automated security-update PRs are off — even after an alert, a human has to write the bump by hand.",
			DocURL:          "/rules/cicd-sec-3-dependabot-fixes-off",
			Frameworks:      []string{FrameworkOWASP},
		},

		// --- Secret scanning (CICD-SEC-6) --------------------------------
		{
			ID:              RuleSecretScanningOff,
			Category:        "CICD-SEC-6",
			Title:           "Secret scanning is disabled",
			DefaultSeverity: SeverityMedium,
			Surface:         SurfaceRepoSettings,
			Description:     "Leaked credentials in commits and pull requests will not be detected.",
			DocURL:          "/rules/cicd-sec-6-secret-scanning-off",
			Frameworks:      []string{FrameworkOWASP},
		},
		{
			ID:              RuleSecretPushProtectionOff,
			Category:        "CICD-SEC-6",
			Title:           "Secret-scanning push protection is disabled",
			DefaultSeverity: SeverityHigh,
			Surface:         SurfaceRepoSettings,
			Description:     "Push protection blocks commits with detected secrets before they reach the remote.",
			DocURL:          "/rules/cicd-sec-6-secret-push-protection-off",
			Frameworks:      []string{FrameworkOWASP},
		},
	}
}

// RuleByID returns a map view of Rules() for O(1) lookups, e.g. when validating
// a rule_id submitted by the API client.
func RuleByID() map[RuleID]RuleSpec {
	all := Rules()
	out := make(map[RuleID]RuleSpec, len(all))
	for _, r := range all {
		out[r.ID] = r
	}
	return out
}

// FilterByEnabledRules drops findings whose RuleID is explicitly disabled.
// Findings with an empty RuleID (synthetic SYSTEM/INFO notices like parse
// errors or settings-audit failures) are never toggleable — they always pass.
// A nil/empty disabled map is a no-op; callers can pass the result of
// EffectiveDisabledRules unconditionally.
func FilterByEnabledRules(findings []Finding, disabled map[RuleID]bool) []Finding {
	if len(disabled) == 0 {
		return findings
	}
	out := findings[:0:0] // fresh backing array; don't alias the input
	for _, f := range findings {
		if f.RuleID != "" && disabled[f.RuleID] {
			continue
		}
		out = append(out, f)
	}
	return out
}
