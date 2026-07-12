package vcs

import (
	"context"
	"strconv"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// This file gives *GitHubClient the provider-neutral method set the
// VCSClient interface (defined in the private pkg/api) requires. The
// GitHub-typed methods (InstallationToken(int64), FetchWorkflows(owner, repo,
// ref), …) stay exported so the CLI and tests keep compiling unchanged; the
// methods below add provider-neutral signatures that dispatch to them.
//
// MintToken/LoadInstallation are NOT here: they take pkg/api's InstallationAuth
// (which carries store-lookup state) and therefore live on the private
// githubVCS wrapper in pkg/api/github_saas.go.

// Provider returns the canonical provider string.
func (g *GitHubClient) Provider() string { return ProviderGitHub }

// DiscoverRepos lists every repository the token can read.
func (g *GitHubClient) DiscoverRepos(ctx context.Context, token string) ([]RepoView, error) {
	repos, err := g.ListRepos(ctx, token)
	if err != nil {
		return nil, err
	}
	out := make([]RepoView, 0, len(repos))
	for _, r := range repos {
		out = append(out, RepoView{
			ProviderRepoID: strconv.FormatInt(r.ID, 10),
			Owner:          r.Owner.Login,
			Name:           r.Name,
			FullName:       r.FullName,
			Private:        r.Private,
			HTMLURL:        r.HTMLURL,
			DefaultBranch:  r.DefaultBranch,
		})
	}
	return out, nil
}

// LoadWorkflows dispatches to the GitHub-typed method.
func (g *GitHubClient) LoadWorkflows(ctx context.Context, token string, repo RepoCoord, ref string) ([]WorkflowFile, error) {
	return g.FetchWorkflows(ctx, token, repo.Owner, repo.Name, ref)
}

// LoadRepoConfig dispatches to the GitHub-typed method.
func (g *GitHubClient) LoadRepoConfig(ctx context.Context, token string, repo RepoCoord, ref string) ([]byte, error) {
	return g.FetchRepoConfig(ctx, token, repo.Owner, repo.Name, ref)
}

// AuditSettings implements VCSClient: fetch the GitHub repository settings and
// run the settings scanner over them, returning the findings.
func (g *GitHubClient) AuditSettings(ctx context.Context, token string, repo RepoCoord, defaultBranch, htmlURL string) ([]scanner.Finding, error) {
	rc, err := g.FetchRepositorySettings(ctx, token, repo.Owner, repo.Name, defaultBranch, htmlURL)
	if err != nil {
		return nil, err
	}
	return scanner.ScanRepositorySettings(*rc), nil
}

// FixSetting dispatches to the GitHub-typed method.
func (g *GitHubClient) FixSetting(ctx context.Context, token string, repo RepoCoord, defaultBranch string, ruleID scanner.RuleID, dryRun bool) (SettingsFixAction, error) {
	return g.FixSingleRepositorySetting(ctx, token, repo.Owner, repo.Name, defaultBranch, ruleID, dryRun)
}

// FixWorkflow dispatches to the GitHub-typed method.
func (g *GitHubClient) FixWorkflow(ctx context.Context, token string, repo RepoCoord, defaultBranch, filePath string, ruleID scanner.RuleID) (ChangeRequestResult, error) {
	return g.FixWorkflowFile(ctx, token, repo.Owner, repo.Name, defaultBranch, filePath, ruleID)
}
