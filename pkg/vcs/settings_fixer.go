package vcs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// SettingsFixAction summarises one repository-settings remediation. The CLI
// prints these in both dry-run and applied modes; the web app returns one to
// the SPA so the Fix button can display "Enabled secret scanning".
type SettingsFixAction struct {
	RuleID      scanner.RuleID `json:"rule_id"`
	Description string         `json:"description"`        // human-readable: "Enabled secret scanning on acme/widgets"
	Endpoint    string         `json:"endpoint,omitempty"` // for debugging: "PATCH /repos/acme/widgets"
}

// SettingsFixResult aggregates the outcome of a FixRepositorySettings call.
type SettingsFixResult struct {
	Applied []SettingsFixAction `json:"applied"`           // mutations the API accepted (or would accept in dry-run)
	Skipped []scanner.RuleID    `json:"skipped,omitempty"` // rule IDs with no auto-fix (a no-op, not an error)
	Errors  []SettingsFixError  `json:"errors,omitempty"`  // per-rule failures; the rest of the run continues
	DryRun  bool                `json:"dry_run"`           // true if Apply was a no-op
}

// SettingsFixError carries a per-rule failure so callers can render which rule
// failed and why without aborting the whole batch.
type SettingsFixError struct {
	RuleID  scanner.RuleID `json:"rule_id"`
	Message string         `json:"message"`
}

// settingsFixerFn is the per-rule remediation entrypoint. It returns the action
// it took (or would take, in dry-run); the dispatcher composes them into a
// SettingsFixResult.
type settingsFixerFn func(ctx context.Context, g *GitHubClient, token, owner, repo, defaultBranch string) (SettingsFixAction, error)

// settingsFixers is the canonical RuleID → fixer mapping. Adding a new
// auto-fixable repo-settings rule is exactly: add a function below, register
// it here, flip the doc page from ✗ to ✓.
var settingsFixers = map[scanner.RuleID]settingsFixerFn{
	// Tier 1 — single PATCH/PUT/POST per rule.
	scanner.RuleWPermWrite:              fixWPermWrite,
	scanner.RuleWPermPRApprove:          fixWPermPRApprove,
	scanner.RuleDependabotAlertsOff:     fixDependabotAlerts,
	scanner.RuleDependabotFixesOff:      fixDependabotFixes,
	scanner.RuleSecretScanningOff:       fixSecretScanning,
	scanner.RuleSecretPushProtectionOff: fixSecretPushProtection,

	// Tier 2 — branch protection (fetch → mutate → PUT).
	scanner.RuleBPMissing:            fixBPMissing,
	scanner.RuleBPForcePush:          fixBPForcePush,
	scanner.RuleBPDeletion:           fixBPDeletion,
	scanner.RuleBPAdminBypass:        fixBPAdminBypass,
	scanner.RuleBPNoCodeownersReview: fixBPNoCodeownersReview,
	scanner.RuleBPNoSignedCommits:    fixBPNoSignedCommits,
}

// IsAutoFixableRepoSetting reports whether the given rule has a registered
// auto-fixer. Web handlers and the CLI both use this to decide whether to
// surface a "Fix" affordance for a finding.
func IsAutoFixableRepoSetting(ruleID scanner.RuleID) bool {
	_, ok := settingsFixers[ruleID]
	return ok
}

// AutoFixableRepoSettingRules returns the sorted slice of rule IDs that have
// a registered auto-fixer. The SPA fetches this once to know which findings
// should render a Fix button.
func AutoFixableRepoSettingRules() []scanner.RuleID {
	out := make([]scanner.RuleID, 0, len(settingsFixers))
	for r := range settingsFixers {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// FixRepositorySettings applies every auto-fixable finding in the input list
// against the GitHub API. Per-rule errors are recorded but never abort the
// batch — the caller can re-run on the residual set after addressing them.
//
// When dryRun is true, no mutating requests are issued; the returned Applied
// list contains the actions that would have been taken.
func (g *GitHubClient) FixRepositorySettings(
	ctx context.Context,
	token, owner, repo, defaultBranch string,
	findings []scanner.Finding,
	dryRun bool,
) SettingsFixResult {
	result := SettingsFixResult{DryRun: dryRun}
	seen := make(map[scanner.RuleID]bool)

	for _, f := range findings {
		if f.RuleID == "" || seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true

		fn, ok := settingsFixers[f.RuleID]
		if !ok {
			result.Skipped = append(result.Skipped, f.RuleID)
			continue
		}
		action, err := g.fixOneSetting(ctx, fn, token, owner, repo, defaultBranch, dryRun)
		if err != nil {
			result.Errors = append(result.Errors, SettingsFixError{
				RuleID:  f.RuleID,
				Message: err.Error(),
			})
			continue
		}
		action.RuleID = f.RuleID
		result.Applied = append(result.Applied, action)
	}
	return result
}

// FixSingleRepositorySetting applies one specific rule's fixer. The web app
// uses this from POST /api/fix-finding to remediate one finding at a time.
func (g *GitHubClient) FixSingleRepositorySetting(
	ctx context.Context,
	token, owner, repo, defaultBranch string,
	ruleID scanner.RuleID,
	dryRun bool,
) (SettingsFixAction, error) {
	fn, ok := settingsFixers[ruleID]
	if !ok {
		return SettingsFixAction{}, fmt.Errorf("no auto-fix available for rule %s", ruleID)
	}
	action, err := g.fixOneSetting(ctx, fn, token, owner, repo, defaultBranch, dryRun)
	if err != nil {
		return SettingsFixAction{}, err
	}
	action.RuleID = ruleID
	return action, nil
}

// fixOneSetting is the dry-run gate. In dry-run, we still need the action's
// description, so the fixer functions are expected to compute and return the
// description even when they short-circuit on dryRun.
func (g *GitHubClient) fixOneSetting(
	ctx context.Context,
	fn settingsFixerFn,
	token, owner, repo, defaultBranch string,
	dryRun bool,
) (SettingsFixAction, error) {
	// Wrap the client so dry-run requests are intercepted before they hit the
	// network. PATCH/PUT/POST/DELETE become no-ops; GETs (e.g. branch-protection
	// fetch-before-mutate) still go through so the action description is accurate.
	if dryRun {
		drClient := *g
		drClient.http = &http.Client{Transport: dryRunTransport{inner: g.http.Transport}}
		return fn(ctx, &drClient, token, owner, repo, defaultBranch)
	}
	return fn(ctx, g, token, owner, repo, defaultBranch)
}

// dryRunTransport short-circuits write methods to a synthetic 200 response so
// fixer code paths run unchanged but never mutate the remote.
type dryRunTransport struct{ inner http.RoundTripper }

func (t dryRunTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		if t.inner != nil {
			return t.inner.RoundTrip(req)
		}
		return http.DefaultTransport.RoundTrip(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// --- Helpers --------------------------------------------------------------

func putJSON(ctx context.Context, g *GitHubClient, token, url string, body interface{}, out interface{}) error {
	return doJSON(ctx, g, http.MethodPut, token, url, body, out)
}

func patchJSON(ctx context.Context, g *GitHubClient, token, url string, body interface{}, out interface{}) error {
	return doJSON(ctx, g, http.MethodPatch, token, url, body, out)
}

func postJSON(ctx context.Context, g *GitHubClient, token, url string, body interface{}, out interface{}) error {
	return doJSON(ctx, g, http.MethodPost, token, url, body, out)
}

func doJSON(ctx context.Context, g *GitHubClient, method, token, url string, body, out interface{}) error {
	var rdr *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		rdr = bytes.NewReader(data)
	}
	// g.do accepts io.Reader; nil is fine for empty body.
	if rdr == nil {
		return g.do(ctx, method, url, token, nil, out)
	}
	return g.do(ctx, method, url, token, rdr, out)
}

// --- Tier 1: workflow permissions (CICD-SEC-4) ----------------------------

// workflowPermsBody mirrors the PUT request shape. GitHub requires both fields
// (the endpoint is replace-style, not patch-style), so we fetch the current
// state, modify the one field we care about, and PUT both back.
type workflowPermsBody struct {
	DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
	CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
}

func fetchWorkflowPerms(ctx context.Context, g *GitHubClient, token, owner, repo string) (workflowPermsBody, error) {
	var current workflowPermsBody
	url := fmt.Sprintf("%s/repos/%s/%s/actions/permissions/workflow", g.api(), owner, repo)
	if err := g.do(ctx, http.MethodGet, url, token, nil, &current); err != nil {
		return current, fmt.Errorf("fetch current workflow permissions: %w", err)
	}
	return current, nil
}

func putWorkflowPerms(ctx context.Context, g *GitHubClient, token, owner, repo string, body workflowPermsBody) error {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/permissions/workflow", g.api(), owner, repo)
	return putJSON(ctx, g, token, url, body, nil)
}

func fixWPermWrite(ctx context.Context, g *GitHubClient, token, owner, repo, _ string) (SettingsFixAction, error) {
	current, err := fetchWorkflowPerms(ctx, g, token, owner, repo)
	if err != nil {
		return SettingsFixAction{}, err
	}
	current.DefaultWorkflowPermissions = "read"
	if err := putWorkflowPerms(ctx, g, token, owner, repo, current); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Set default GITHUB_TOKEN permissions to read on %s/%s", owner, repo),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/actions/permissions/workflow", owner, repo),
	}, nil
}

func fixWPermPRApprove(ctx context.Context, g *GitHubClient, token, owner, repo, _ string) (SettingsFixAction, error) {
	current, err := fetchWorkflowPerms(ctx, g, token, owner, repo)
	if err != nil {
		return SettingsFixAction{}, err
	}
	current.CanApprovePullRequestReviews = false
	if err := putWorkflowPerms(ctx, g, token, owner, repo, current); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Disallowed GitHub Actions from approving pull requests on %s/%s", owner, repo),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/actions/permissions/workflow", owner, repo),
	}, nil
}

// --- Tier 1: Dependabot (CICD-SEC-3) --------------------------------------

func fixDependabotAlerts(ctx context.Context, g *GitHubClient, token, owner, repo, _ string) (SettingsFixAction, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/vulnerability-alerts", g.api(), owner, repo)
	if err := putJSON(ctx, g, token, url, nil, nil); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Enabled Dependabot vulnerability alerts on %s/%s", owner, repo),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/vulnerability-alerts", owner, repo),
	}, nil
}

func fixDependabotFixes(ctx context.Context, g *GitHubClient, token, owner, repo, _ string) (SettingsFixAction, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/automated-security-fixes", g.api(), owner, repo)
	if err := putJSON(ctx, g, token, url, nil, nil); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Enabled Dependabot security updates on %s/%s", owner, repo),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/automated-security-fixes", owner, repo),
	}, nil
}

// --- Tier 1: Secret scanning (CICD-SEC-6) ---------------------------------

// secAnalysisBody is the PATCH /repos shape for toggling secret-scanning
// features. Each pointer field is omitted when nil so a single fix only
// touches its own toggle.
type secAnalysisBody struct {
	SecurityAndAnalysis secAnalysisInner `json:"security_and_analysis"`
}

type secAnalysisInner struct {
	SecretScanning               *secAnalysisStatus `json:"secret_scanning,omitempty"`
	SecretScanningPushProtection *secAnalysisStatus `json:"secret_scanning_push_protection,omitempty"`
}

type secAnalysisStatus struct {
	Status string `json:"status"`
}

func patchSecAnalysis(ctx context.Context, g *GitHubClient, token, owner, repo string, body secAnalysisBody) error {
	url := fmt.Sprintf("%s/repos/%s/%s", g.api(), owner, repo)
	return patchJSON(ctx, g, token, url, body, nil)
}

func fixSecretScanning(ctx context.Context, g *GitHubClient, token, owner, repo, _ string) (SettingsFixAction, error) {
	body := secAnalysisBody{SecurityAndAnalysis: secAnalysisInner{
		SecretScanning: &secAnalysisStatus{Status: "enabled"},
	}}
	if err := patchSecAnalysis(ctx, g, token, owner, repo, body); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Enabled secret scanning on %s/%s", owner, repo),
		Endpoint:    fmt.Sprintf("PATCH /repos/%s/%s", owner, repo),
	}, nil
}

func fixSecretPushProtection(ctx context.Context, g *GitHubClient, token, owner, repo, _ string) (SettingsFixAction, error) {
	body := secAnalysisBody{SecurityAndAnalysis: secAnalysisInner{
		SecretScanningPushProtection: &secAnalysisStatus{Status: "enabled"},
	}}
	if err := patchSecAnalysis(ctx, g, token, owner, repo, body); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Enabled secret-scanning push protection on %s/%s", owner, repo),
		Endpoint:    fmt.Sprintf("PATCH /repos/%s/%s", owner, repo),
	}, nil
}

// --- Tier 2: branch protection (CICD-SEC-1) -------------------------------
//
// GitHub's branch-protection API is replace-style: PUT takes a complete
// description of the protection rule and replaces the existing one. Helpers
// below fetch the current rule, mutate one field, and PUT the result so a
// single fix doesn't relax other policies the user already set.
//
// The PUT body shape differs from the GET response shape — most notably,
// nested objects like required_pull_request_reviews/required_status_checks
// are nullable in the PUT (set to null to remove the requirement). We model
// only the fields we touch.

type bpPutBody struct {
	RequiredStatusChecks       *bpStatusChecks `json:"required_status_checks"`
	EnforceAdmins              bool            `json:"enforce_admins"`
	RequiredPullRequestReviews *bpPRReviews    `json:"required_pull_request_reviews"`
	Restrictions               *bpRestrictions `json:"restrictions"`
	AllowForcePushes           *bool           `json:"allow_force_pushes,omitempty"`
	AllowDeletions             *bool           `json:"allow_deletions,omitempty"`
}

type bpStatusChecks struct {
	Strict   bool     `json:"strict"`
	Contexts []string `json:"contexts"`
}

type bpPRReviews struct {
	DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
	RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
}

// bpRestrictions: present only for org-owned repos and complex to populate
// safely. We always send null (no restrictions) — this fixer doesn't manage
// per-team push allowlists.
type bpRestrictions struct {
	Users []string `json:"users"`
	Teams []string `json:"teams"`
}

// fetchBranchProtectionForPut returns the current protection rule in the
// shape required for a PUT replacement. Pulled separately from the scanner's
// FetchRepositorySettings because we need the full body, not the scanner's
// reduced view.
func fetchBranchProtectionForPut(ctx context.Context, g *GitHubClient, token, owner, repo, branch string) (bpPutBody, bool, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection", g.api(), owner, repo, branch)

	// GitHub's GET response embeds each scalar in an {"enabled": bool} wrapper.
	// We decode into the response shape and re-pack into the PUT shape.
	var raw struct {
		RequiredStatusChecks       *bpStatusChecks         `json:"required_status_checks"`
		EnforceAdmins              *struct{ Enabled bool } `json:"enforce_admins"`
		RequiredPullRequestReviews *bpPRReviews            `json:"required_pull_request_reviews"`
		AllowForcePushes           *struct{ Enabled bool } `json:"allow_force_pushes"`
		AllowDeletions             *struct{ Enabled bool } `json:"allow_deletions"`
	}
	err := g.do(ctx, http.MethodGet, url, token, nil, &raw)
	if err != nil {
		if StatusOf(err) == http.StatusNotFound {
			return bpPutBody{}, false, nil
		}
		return bpPutBody{}, false, err
	}

	body := bpPutBody{
		RequiredStatusChecks:       raw.RequiredStatusChecks,
		RequiredPullRequestReviews: raw.RequiredPullRequestReviews,
		Restrictions:               nil,
	}
	if raw.EnforceAdmins != nil {
		body.EnforceAdmins = raw.EnforceAdmins.Enabled
	}
	if raw.AllowForcePushes != nil {
		v := raw.AllowForcePushes.Enabled
		body.AllowForcePushes = &v
	}
	if raw.AllowDeletions != nil {
		v := raw.AllowDeletions.Enabled
		body.AllowDeletions = &v
	}
	return body, true, nil
}

func putBranchProtection(ctx context.Context, g *GitHubClient, token, owner, repo, branch string, body bpPutBody) error {
	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection", g.api(), owner, repo, branch)
	return putJSON(ctx, g, token, url, body, nil)
}

// fixBPMissing creates a sensible default branch-protection rule on the
// default branch. The defaults follow common hardening guidance: 2 reviews
// required, dismiss stale reviews on push, enforce against admins, no force
// pushes or deletions.
func fixBPMissing(ctx context.Context, g *GitHubClient, token, owner, repo, defaultBranch string) (SettingsFixAction, error) {
	false_ := false
	body := bpPutBody{
		RequiredStatusChecks: nil,
		EnforceAdmins:        true,
		RequiredPullRequestReviews: &bpPRReviews{
			DismissStaleReviews:          true,
			RequireCodeOwnerReviews:      false,
			RequiredApprovingReviewCount: 2,
		},
		Restrictions:     nil,
		AllowForcePushes: &false_,
		AllowDeletions:   &false_,
	}
	if err := putBranchProtection(ctx, g, token, owner, repo, defaultBranch, body); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Created branch protection on %s/%s@%s (2 reviews, dismiss stale, enforce admins, no force-push or deletion)", owner, repo, defaultBranch),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/branches/%s/protection", owner, repo, defaultBranch),
	}, nil
}

func fetchOrEmptyProtection(ctx context.Context, g *GitHubClient, token, owner, repo, branch string) (bpPutBody, error) {
	body, found, err := fetchBranchProtectionForPut(ctx, g, token, owner, repo, branch)
	if err != nil {
		return bpPutBody{}, err
	}
	if !found {
		return bpPutBody{}, fmt.Errorf("no branch protection on %s — run the BP-MISSING fix first", branch)
	}
	return body, nil
}

func fixBPForcePush(ctx context.Context, g *GitHubClient, token, owner, repo, defaultBranch string) (SettingsFixAction, error) {
	body, err := fetchOrEmptyProtection(ctx, g, token, owner, repo, defaultBranch)
	if err != nil {
		return SettingsFixAction{}, err
	}
	false_ := false
	body.AllowForcePushes = &false_
	if err := putBranchProtection(ctx, g, token, owner, repo, defaultBranch, body); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Disabled force pushes on %s/%s@%s", owner, repo, defaultBranch),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/branches/%s/protection", owner, repo, defaultBranch),
	}, nil
}

func fixBPDeletion(ctx context.Context, g *GitHubClient, token, owner, repo, defaultBranch string) (SettingsFixAction, error) {
	body, err := fetchOrEmptyProtection(ctx, g, token, owner, repo, defaultBranch)
	if err != nil {
		return SettingsFixAction{}, err
	}
	false_ := false
	body.AllowDeletions = &false_
	if err := putBranchProtection(ctx, g, token, owner, repo, defaultBranch, body); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Disallowed branch deletion on %s/%s@%s", owner, repo, defaultBranch),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/branches/%s/protection", owner, repo, defaultBranch),
	}, nil
}

func fixBPAdminBypass(ctx context.Context, g *GitHubClient, token, owner, repo, defaultBranch string) (SettingsFixAction, error) {
	body, err := fetchOrEmptyProtection(ctx, g, token, owner, repo, defaultBranch)
	if err != nil {
		return SettingsFixAction{}, err
	}
	body.EnforceAdmins = true
	if err := putBranchProtection(ctx, g, token, owner, repo, defaultBranch, body); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Enabled enforce_admins on %s/%s@%s", owner, repo, defaultBranch),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/branches/%s/protection", owner, repo, defaultBranch),
	}, nil
}

func fixBPNoCodeownersReview(ctx context.Context, g *GitHubClient, token, owner, repo, defaultBranch string) (SettingsFixAction, error) {
	body, err := fetchOrEmptyProtection(ctx, g, token, owner, repo, defaultBranch)
	if err != nil {
		return SettingsFixAction{}, err
	}
	if body.RequiredPullRequestReviews == nil {
		body.RequiredPullRequestReviews = &bpPRReviews{RequiredApprovingReviewCount: 1}
	}
	body.RequiredPullRequestReviews.RequireCodeOwnerReviews = true
	if err := putBranchProtection(ctx, g, token, owner, repo, defaultBranch, body); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Required CODEOWNERS review on %s/%s@%s", owner, repo, defaultBranch),
		Endpoint:    fmt.Sprintf("PUT /repos/%s/%s/branches/%s/protection", owner, repo, defaultBranch),
	}, nil
}

// fixBPNoSignedCommits uses the dedicated required_signatures endpoint
// rather than the full branch-protection PUT — it's a separate sub-resource.
func fixBPNoSignedCommits(ctx context.Context, g *GitHubClient, token, owner, repo, defaultBranch string) (SettingsFixAction, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection/required_signatures", g.api(), owner, repo, defaultBranch)
	if err := postJSON(ctx, g, token, url, nil, nil); err != nil {
		return SettingsFixAction{}, err
	}
	return SettingsFixAction{
		Description: fmt.Sprintf("Required signed commits on %s/%s@%s", owner, repo, defaultBranch),
		Endpoint:    fmt.Sprintf("POST /repos/%s/%s/branches/%s/protection/required_signatures", owner, repo, defaultBranch),
	}, nil
}
