package vcs

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// Auto-fix coverage for workflow YAML rules. These are the rule IDs whose
// fixers live in pkg/scanner/fixer.go's FixBytes dispatcher — keep this list
// in lockstep with the case branches there.
//
// Unlike repo-settings rules (which mutate GitHub-side config via PATCH/PUT),
// workflow-YAML fixes change file content. The web app applies them by
// fetching the file, running FixBytes in memory, and opening a PR/MR with the
// diff. The CLI runs FixBytes locally via --fix; both paths share the
// scanner.FixBytes core.
var workflowFixableRules = map[scanner.RuleID]bool{
	scanner.RulePPECheckout:          true, // CICD-SEC-1
	scanner.RuleUnpinnedAction:       true, // CICD-SEC-3
	scanner.RulePPEShellInjection:    true, // CICD-SEC-4
	scanner.RuleMissingPermissions:   true, // CICD-SEC-5
	scanner.RuleHardcodedSecrets:     true, // CICD-SEC-6
	scanner.RuleDebugLoggingEnabled:  true, // CICD-SEC-7
	scanner.RuleContinueOnErrorJob:   true, // CICD-SEC-10
	scanner.RuleSLSAOIDCTokenScope:   true, // SLSA-BUILD-L2
	scanner.RuleSLSAPermsOverlyBroad: true, // SLSA-BUILD-L2 (scalar write-all only)
	scanner.RuleMissingTimeout:       true, // BEST-PRAC-2
	scanner.RuleUnsoundCondition:     true, // CICD-SEC-1 (operator-only residue)
	scanner.RuleMissingConcurrency:   true, // BEST-PRAC-4

	// Comment-only advisories: the replacement needs an identity that does
	// not exist in the file, so the fix annotates the line rather than
	// rewriting it. See fixCloudStaticCredentials.
	scanner.RuleCloudStaticCredentials: true, // CICD-SEC-2
	scanner.RulePRTargetDualTrigger:    true, // CICD-SEC-1 (trigger block only)

	// GitLab CI fixers — conservative trio shipped in the parity v1.
	scanner.RuleGitLabDebugTrace:     true, // CICD-SEC-7 (gl)
	scanner.RuleGitLabAllowFailure:   true, // CICD-SEC-10 (gl)
	scanner.RuleGitLabMissingTimeout: true, // BEST-PRAC-2 (gl)
}

// IsAutoFixableWorkflowRule reports whether the given rule has a workflow-YAML
// auto-fixer available. Used by the handler to decide between the repo-settings
// fix path and the workflow PR-fix path, and by the SPA to decide which
// findings get a Fix button.
func IsAutoFixableWorkflowRule(ruleID scanner.RuleID) bool {
	return workflowFixableRules[ruleID]
}

// AutoFixableWorkflowRules returns the sorted slice of workflow rule IDs that
// the API can remediate via PR. The SPA fetches this once to render the per-
// finding Fix button for the right subset.
func AutoFixableWorkflowRules() []scanner.RuleID {
	out := make([]scanner.RuleID, 0, len(workflowFixableRules))
	for r := range workflowFixableRules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// FixWorkflowFile is the 5-step Git Data dance that remediates one workflow
// finding by opening a PR. The provider-neutral result type
// (ChangeRequestResult) is shared with the GitLab MR remediation path so the
// handler envelope renders both the same way.
//
//  1. Fetch the file's current bytes + blob SHA from the default branch.
//  2. Re-scan the fresh content for the target rule, then run scanner.FixBytes
//     against those findings; bail out if no fix matched (the file may have
//     been fixed manually between the SPA scan and the user's Fix click).
//  3. Create (or reuse) a deterministic branch from the default branch's HEAD.
//  4. PUT the new content to that branch via the Contents API.
//  5. Open a PR (or return the existing one) from the branch to the default branch.
//
// We re-scan in step 2 (rather than trusting line/col from the SPA-cached
// finding) so the fix is always grounded in the actual content being mutated.
func (g *GitHubClient) FixWorkflowFile(
	ctx context.Context,
	token, owner, repo, defaultBranch, filePath string,
	ruleID scanner.RuleID,
) (ChangeRequestResult, error) {
	res := ChangeRequestResult{Provider: ProviderGitHub, RuleID: ruleID, File: filePath}

	if !IsAutoFixableWorkflowRule(ruleID) {
		return res, fmt.Errorf("rule %s has no workflow auto-fix", ruleID)
	}

	return g.fixWorkflowFileWith(ctx, token, owner, repo, defaultBranch, filePath, res,
		func(fresh []scanner.Finding) []scanner.Finding {
			return scopedFindings(fresh, ruleID, filePath)
		},
		workflowFixNaming{
			branch: ChangeBranchName(ruleID, filePath),
			commit: ChangeCommitMessage(ruleID, filePath),
			title:  ChangeRequestTitle(ruleID),
			body: func(fixesCount int) string {
				return ChangeRequestBody(ruleID, filePath, fixesCount)
			},
		})
}

// FixWorkflowFileRules remediates *every* requested rule in one file with a
// single change request — the bulk-remediation campaign path.
//
// The per-rule FixWorkflowFile above is still the right call for the
// per-finding "Fix" button, where the user asked for exactly one fix. But a
// campaign fixing a workflow with five findings would otherwise open five PRs
// against the same file, each branched independently off the default branch:
// noisy to review, and the ones touching the same region conflict as soon as a
// sibling merges. Batching gives one branch, one commit, one PR per file.
//
// Rules without a workflow auto-fixer are ignored rather than fatal, so a
// caller can pass everything it found; ErrChangeRequestNoChange is returned
// when none of them still apply to the fetched content.
func (g *GitHubClient) FixWorkflowFileRules(
	ctx context.Context,
	token, owner, repo, defaultBranch, filePath string,
	ruleIDs []scanner.RuleID,
) (ChangeRequestResult, error) {
	fixable := fixableRules(ruleIDs)
	res := ChangeRequestResult{Provider: ProviderGitHub, RuleIDs: fixable, File: filePath}
	if len(fixable) == 0 {
		return res, fmt.Errorf("no auto-fixable workflow rules requested for %s", filePath)
	}

	return g.fixWorkflowFileWith(ctx, token, owner, repo, defaultBranch, filePath, res,
		func(fresh []scanner.Finding) []scanner.Finding {
			return scopedFindingsForRules(fresh, fixable, filePath)
		},
		workflowFixNaming{
			branch: ChangeBranchNameForFile(filePath),
			commit: ChangeCommitMessageForFile(filePath, len(fixable)),
			title:  ChangeRequestTitleForFile(filePath),
			body: func(fixesCount int) string {
				return ChangeRequestBodyForFile(filePath, fixable, fixesCount)
			},
		})
}

// workflowFixNaming supplies the strings that distinguish a per-rule change
// request from a batched, file-scoped one. The body is a callback because the
// fix count is only known once the fixer has run.
type workflowFixNaming struct {
	branch string
	commit string
	title  string
	body   func(fixesCount int) string
}

// fixWorkflowFileWith is the 5-step Git Data dance itself, shared by the
// per-rule and batched entry points. selectFindings narrows the fresh scan to
// the findings this change request should remediate.
func (g *GitHubClient) fixWorkflowFileWith(
	ctx context.Context,
	token, owner, repo, defaultBranch, filePath string,
	res ChangeRequestResult,
	selectFindings func([]scanner.Finding) []scanner.Finding,
	naming workflowFixNaming,
) (ChangeRequestResult, error) {
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// 1. Fetch the file from the default branch.
	current, currentSHA, err := g.fetchFileContents(ctx, token, owner, repo, filePath, defaultBranch)
	if err != nil {
		return res, fmt.Errorf("fetch %s: %w", filePath, err)
	}

	// 2. Re-scan the fresh content and apply the fixer(s). scanner.FixBytes
	// applies every finding it is handed in one pass over one YAML document,
	// which is what lets the batched path produce a single commit.
	fresh, err := scanner.ScanBytes(filePath, current)
	if err != nil {
		return res, fmt.Errorf("scan %s: %w", filePath, err)
	}
	scoped := selectFindings(fresh)
	if len(scoped) == 0 {
		res.NoChange = true
		return res, ErrChangeRequestNoChange
	}
	newContent, fixesCount, err := scanner.FixBytes(current, scoped)
	if err != nil {
		return res, fmt.Errorf("apply fix: %w", err)
	}
	if newContent == nil || fixesCount == 0 {
		res.NoChange = true
		return res, ErrChangeRequestNoChange
	}
	res.FixesApplied = fixesCount

	// 3. Create (or reuse) the deterministic fix branch.
	branchName := naming.branch
	res.BranchName = branchName
	if err := g.ensureFixBranch(ctx, token, owner, repo, defaultBranch, branchName); err != nil {
		return res, fmt.Errorf("ensure branch %s: %w", branchName, err)
	}

	// 4. PUT the new content on the branch. Re-fetch the file's SHA on the
	// branch in case a previous click already pushed a version we'd otherwise
	// clobber blindly.
	branchSHA := currentSHA
	if existing, sha, err := g.fetchFileContents(ctx, token, owner, repo, filePath, branchName); err == nil {
		if string(existing) == string(newContent) {
			branchSHA = sha
		} else {
			branchSHA = sha
			if err := g.putFileContents(ctx, token, owner, repo, filePath, branchName, newContent, sha, naming.commit); err != nil {
				return res, fmt.Errorf("put %s on %s: %w", filePath, branchName, err)
			}
		}
	} else {
		if err := g.putFileContents(ctx, token, owner, repo, filePath, branchName, newContent, branchSHA, naming.commit); err != nil {
			return res, fmt.Errorf("put %s on %s: %w", filePath, branchName, err)
		}
	}

	// 5. Open the PR (or reuse the existing one for this head ref).
	prURL, prNumber, reused, err := g.openOrReusePR(ctx, token, owner, repo, defaultBranch, branchName, naming.title, naming.body(fixesCount))
	if err != nil {
		return res, fmt.Errorf("open PR: %w", err)
	}
	res.URL = prURL
	res.Number = prNumber
	res.Reused = reused
	return res, nil
}

// fixableRules returns the deduped, sorted subset of the requested rules that
// actually has a workflow auto-fixer. Sorting keeps the branch content, commit
// message, and PR body deterministic regardless of the caller's ordering.
func fixableRules(ruleIDs []scanner.RuleID) []scanner.RuleID {
	seen := make(map[scanner.RuleID]bool, len(ruleIDs))
	out := make([]scanner.RuleID, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		if seen[id] || !IsAutoFixableWorkflowRule(id) {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// scopedFindingsForRules is scopedFindings' batched twin: it keeps every
// finding for this file whose rule is in the requested set.
func scopedFindingsForRules(findings []scanner.Finding, ruleIDs []scanner.RuleID, filePath string) []scanner.Finding {
	want := make(map[scanner.RuleID]bool, len(ruleIDs))
	for _, id := range ruleIDs {
		want[id] = true
	}
	out := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		if !want[f.RuleID] {
			continue
		}
		if f.File != "" && f.File != filePath {
			continue
		}
		out = append(out, f)
	}
	return out
}

// scopedFindings narrows the input slice to findings matching the rule ID
// and (for workflow findings) the file path. Belt-and-suspenders: the
// dispatcher in FixBytes already keys on Category/RuleID, but feeding it a
// narrower set keeps the diff focused on the one finding the user clicked.
func scopedFindings(findings []scanner.Finding, ruleID scanner.RuleID, filePath string) []scanner.Finding {
	out := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID != ruleID {
			continue
		}
		if f.File != "" && f.File != filePath {
			continue
		}
		out = append(out, f)
	}
	return out
}

// --- GitHub API call helpers ---------------------------------------------

// fetchFileContents reads a file from the given ref. Returns decoded bytes
// + the file's blob SHA (needed for subsequent PUTs to avoid lost-update
// errors against the Contents API).
func (g *GitHubClient) fetchFileContents(ctx context.Context, token, owner, repo, path, ref string) ([]byte, string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s", g.api(), owner, repo, path, ref)
	var resp struct {
		SHA      string `json:"sha"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := g.do(ctx, http.MethodGet, url, token, nil, &resp); err != nil {
		return nil, "", err
	}
	if resp.Encoding != "base64" {
		return nil, "", fmt.Errorf("unsupported encoding %q for %s", resp.Encoding, path)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(resp.Content, "\n", ""))
	if err != nil {
		return nil, "", fmt.Errorf("decode base64 for %s: %w", path, err)
	}
	return decoded, resp.SHA, nil
}

// putFileContents updates a file on a branch via the Contents API. The
// existing blob SHA must be supplied so GitHub can detect concurrent writes
// and return 409.
func (g *GitHubClient) putFileContents(ctx context.Context, token, owner, repo, path, branch string, content []byte, existingSHA, message string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", g.api(), owner, repo, path)
	body := map[string]interface{}{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  branch,
	}
	if existingSHA != "" {
		body["sha"] = existingSHA
	}
	return putJSON(ctx, g, token, url, body, nil)
}

// ensureFixBranch creates a branch from the default branch's HEAD. If the
// branch already exists, GitHub returns 422 — we treat that as success and
// fall through, since a deterministic fix branch is meant to be reused.
func (g *GitHubClient) ensureFixBranch(ctx context.Context, token, owner, repo, baseBranch, newBranch string) error {
	headSHA, err := g.fetchBranchHeadSHA(ctx, token, owner, repo, baseBranch)
	if err != nil {
		return fmt.Errorf("resolve %s HEAD: %w", baseBranch, err)
	}
	url := fmt.Sprintf("%s/repos/%s/%s/git/refs", g.api(), owner, repo)
	body := map[string]string{
		"ref": "refs/heads/" + newBranch,
		"sha": headSHA,
	}
	err = postJSON(ctx, g, token, url, body, nil)
	if err == nil {
		return nil
	}
	if StatusOf(err) == http.StatusUnprocessableEntity {
		return nil
	}
	return err
}

func (g *GitHubClient) fetchBranchHeadSHA(ctx context.Context, token, owner, repo, branch string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/ref/heads/%s", g.api(), owner, repo, branch)
	var resp struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := g.do(ctx, http.MethodGet, url, token, nil, &resp); err != nil {
		return "", err
	}
	if resp.Object.SHA == "" {
		return "", fmt.Errorf("branch %s has no head SHA", branch)
	}
	return resp.Object.SHA, nil
}

// openOrReusePR opens a pull request from headBranch into baseBranch, or
// returns the existing open PR if one is already pointing at headBranch.
func (g *GitHubClient) openOrReusePR(ctx context.Context, token, owner, repo, baseBranch, headBranch, title, body string) (string, int, bool, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", g.api(), owner, repo)
	create := map[string]string{
		"title": title,
		"head":  headBranch,
		"base":  baseBranch,
		"body":  body,
	}
	var resp struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}
	err := postJSON(ctx, g, token, url, create, &resp)
	if err == nil {
		return resp.HTMLURL, resp.Number, false, nil
	}
	if StatusOf(err) != http.StatusUnprocessableEntity {
		return "", 0, false, err
	}
	existing, lookupErr := g.findOpenPRByHead(ctx, token, owner, repo, headBranch)
	if lookupErr != nil {
		return "", 0, false, fmt.Errorf("create PR failed (422) and lookup failed: %v / %w", err, lookupErr)
	}
	return existing.HTMLURL, existing.Number, true, nil
}

type prSummary struct {
	HTMLURL string `json:"html_url"`
	Number  int    `json:"number"`
}

func (g *GitHubClient) findOpenPRByHead(ctx context.Context, token, owner, repo, headBranch string) (*prSummary, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls?state=open&head=%s:%s", g.api(), owner, repo, owner, headBranch)
	var list []prSummary
	if err := g.do(ctx, http.MethodGet, url, token, nil, &list); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no open PR found for head ref %s", headBranch)
	}
	return &list[0], nil
}
