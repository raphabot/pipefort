package vcs

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// ProviderGitHub / ProviderGitLab are the canonical provider strings written
// to installations.provider and returned by each client's Provider() method.
const (
	ProviderGitHub = "github"
	ProviderGitLab = "gitlab"
)

// RepoCoord uniquely identifies a repository across providers. Owner+Name
// works for both GitHub (owner/name) and GitLab (group-path/project-name).
// ID is the provider's numeric repo id when callers know it — required for
// GitLab API URLs (which use the numeric project id), optional for GitHub.
type RepoCoord struct {
	Owner string
	Name  string
	ID    string // provider repo id as a string ("" when unknown)
}

// RepoView is the provider-neutral shape of one repository.
type RepoView struct {
	ProviderRepoID string // numeric (as string) for GitHub/GitLab
	Owner          string
	Name           string
	FullName       string
	Private        bool
	HTMLURL        string
	DefaultBranch  string
}

// ChangeRequestResult describes the outcome of FixWorkflow. The single result
// shape covers both GitHub Pull Requests and GitLab Merge Requests; the
// handler envelope (handleFixFinding) carries the provider so the SPA can
// label the link "Pull request" vs "Merge request".
type ChangeRequestResult struct {
	Provider     string         `json:"provider"`
	RuleID       scanner.RuleID `json:"rule_id"`
	File         string         `json:"file"`
	FixesApplied int            `json:"fixes_applied"`
	URL          string         `json:"url"`    // PR html_url for GitHub, MR web_url for GitLab
	Number       int            `json:"number"` // PR number for GitHub, MR iid for GitLab
	BranchName   string         `json:"branch_name"`
	Reused       bool           `json:"reused"`    // true when an existing PR/MR was returned without re-fixing
	NoChange     bool           `json:"no_change"` // true when FixBytes produced no diff
}

// ErrChangeRequestNoChange signals that the fetched file did not need any
// change for the given rule. Handlers turn this into 409 to render
// "already fixed" instead of "error".
var ErrChangeRequestNoChange = errors.New("change request produced no change")

// ErrSettingsNotSupported is returned by clients for providers (currently
// GitLab) without an implemented settings audit/fix surface. The scan path
// treats it as a non-fatal "skip the settings audit".
var ErrSettingsNotSupported = errors.New("repository-settings surface not supported for this provider")

// --- Shared helpers (provider-neutral) -------------------------------------
//
// branchSafeFilename and ChangeBranchName are used by both the GitHub PR
// remediation and the GitLab MR remediation to derive a deterministic
// per-(rule, file) branch name. Re-fix clicks converge on a single PR/MR
// rather than spawning duplicates.

var nonSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

// branchSafeFilename derives a slug-safe component from a workflow path like
// ".github/workflows/ci.yml" or ".gitlab-ci.yml".
func branchSafeFilename(filePath string) string {
	base := filePath
	if idx := strings.LastIndex(filePath, "/"); idx >= 0 {
		base = filePath[idx+1:]
	}
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[:idx]
	}
	base = strings.ToLower(base)
	base = nonSlugRe.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "workflow"
	}
	return base
}

// ChangeBranchName composes the deterministic remediation branch name shared
// by GitHub PR and GitLab MR remediation.
func ChangeBranchName(ruleID scanner.RuleID, filePath string) string {
	return fmt.Sprintf("pipefort/fix/%s/%s", string(ruleID), branchSafeFilename(filePath))
}

// ChangeRequestTitle / ChangeRequestBody are shared between providers so the
// PR and MR bodies read the same.
func ChangeRequestTitle(ruleID scanner.RuleID) string {
	spec, ok := scanner.RuleByID()[ruleID]
	if !ok {
		return fmt.Sprintf("Pipefort fix: %s", ruleID)
	}
	return fmt.Sprintf("Pipefort fix: %s", spec.Title)
}

func ChangeRequestBody(ruleID scanner.RuleID, filePath string, fixesCount int) string {
	spec, ok := scanner.RuleByID()[ruleID]
	docLink := "https://docs.pipefort.com/rules/overview"
	if ok && spec.DocURL != "" {
		docLink = "https://docs.pipefort.com" + spec.DocURL
	}
	return fmt.Sprintf(
		"Pipefort detected `%s` in `%s` and rewrote the CI YAML to remediate it (%d change%s).\n\n"+
			"Rule: [%s](%s)\n\n"+
			"Review the diff carefully before merging — auto-fixers are conservative but assume the fixed shape works for your specific deployment.\n",
		ruleID, filePath, fixesCount, plural(fixesCount), ruleID, docLink,
	)
}

// ChangeCommitMessage is the commit message used when committing the rewritten
// CI YAML file to the remediation branch.
func ChangeCommitMessage(ruleID scanner.RuleID, filePath string) string {
	return fmt.Sprintf("Pipefort: fix %s in %s", ruleID, filePath)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
