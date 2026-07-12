package vcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// GitLabClient talks to the GitLab REST API with a caller-supplied per-request
// bearer token. The same client instance handles both gitlab.com and
// self-hosted hosts; the host is supplied per call, falling back to
// defaultHost. Token minting/refresh and the OAuth token store live in the
// private pkg/api gitlabVCS wrapper — this client is store-agnostic.
type GitLabClient struct {
	defaultHost  string
	http         *http.Client
	baseOverride string // tests only — when set, overrides "https://{host}/api/v4"
}

// NewGitLabClient builds a GitLab client for the given default host (empty →
// gitlab.com). The SaaS wrapper (pkg/api) supplies the configured host; the
// caller passes a pre-minted token to every method.
func NewGitLabClient(defaultHost string, opts ...Option) *GitLabClient {
	if defaultHost == "" {
		defaultHost = "gitlab.com"
	}
	c := &GitLabClient{
		defaultHost: defaultHost,
		http:        &http.Client{Timeout: 25 * time.Second},
	}
	applyGitLabOptions(c, newClientOptions(opts))
	return c
}

// NewBareGitLabClient returns a GitLabClient for a caller-held token: the CLI
// uses this for --fix-mr against a user-supplied --gitlab-token. Pass an
// explicit host for self-hosted instances; gitlab.com is the default.
func NewBareGitLabClient(host string, opts ...Option) *GitLabClient {
	return NewGitLabClient(host, opts...)
}

func applyGitLabOptions(c *GitLabClient, o clientOptions) {
	if o.baseURL != "" {
		c.baseOverride = o.baseURL
	}
	if o.httpClient != nil {
		c.http = o.httpClient
	}
}

// Provider returns the canonical provider string.
func (g *GitLabClient) Provider() string { return ProviderGitLab }

// api composes the API base URL for the given host. Self-hosted instances are
// addressed by their bare hostname; SaaS uses gitlab.com when host is empty.
func (g *GitLabClient) api(host string) string {
	if g.baseOverride != "" {
		return g.baseOverride
	}
	if host == "" {
		host = g.defaultHost
		if host == "" {
			host = "gitlab.com"
		}
	}
	return "https://" + host + "/api/v4"
}

// CurrentUser returns the OAuth identity (login, avatar URL) for the given
// token. The SaaS callback uses it to populate the installations row.
func (g *GitLabClient) CurrentUser(ctx context.Context, host, token string) (login, avatarURL string, err error) {
	var resp struct {
		Username  string `json:"username"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := g.do(ctx, http.MethodGet, g.api(host)+"/user", token, nil, &resp); err != nil {
		return "", "", err
	}
	return resp.Username, resp.AvatarURL, nil
}

// gitlabProject is the subset of GitLab's /projects response we care about.
type gitlabProject struct {
	ID                int64  `json:"id"`
	Path              string `json:"path"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	DefaultBranch     string `json:"default_branch"`
	Visibility        string `json:"visibility"`
	Namespace         struct {
		Path string `json:"path"`
	} `json:"namespace"`
}

// DiscoverRepos implements VCSClient. Paginates /projects?membership=true at
// developer access (the minimum required to read CI config + open MRs).
func (g *GitLabClient) DiscoverRepos(ctx context.Context, token string) ([]RepoView, error) {
	// We deliberately don't pass a host here because the token + base URL
	// were already resolved by the caller via MintToken. We re-resolve from
	// the configured default host; self-hosted callers must use a separate
	// GitLabClient with the right host. In practice the handler holds the
	// host on the installation and only calls one client per installation,
	// so this is safe.
	host := g.defaultHost
	if host == "" {
		host = "gitlab.com"
	}
	return g.discoverReposOnHost(ctx, token, host)
}

func (g *GitLabClient) discoverReposOnHost(ctx context.Context, token, host string) ([]RepoView, error) {
	var out []RepoView
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/projects?membership=true&min_access_level=30&per_page=100&page=%d", g.api(host), page)
		var batch []gitlabProject
		if err := g.do(ctx, http.MethodGet, u, token, nil, &batch); err != nil {
			return nil, err
		}
		for _, p := range batch {
			owner, name := splitNamespace(p.PathWithNamespace)
			if owner == "" {
				owner = p.Namespace.Path
				name = p.Path
			}
			out = append(out, RepoView{
				ProviderRepoID: strconv.FormatInt(p.ID, 10),
				Owner:          owner,
				Name:           name,
				FullName:       p.PathWithNamespace,
				Private:        p.Visibility != "public",
				HTMLURL:        p.WebURL,
				DefaultBranch:  p.DefaultBranch,
			})
		}
		if len(batch) < 100 {
			break
		}
	}
	return out, nil
}

// splitNamespace splits "group/sub/project" into ("group/sub", "project").
// Group-only paths (no slash) return ("", path).
func splitNamespace(pathWithNamespace string) (owner, name string) {
	idx := strings.LastIndex(pathWithNamespace, "/")
	if idx < 0 {
		return "", pathWithNamespace
	}
	return pathWithNamespace[:idx], pathWithNamespace[idx+1:]
}

// LoadWorkflows implements VCSClient. Returns the root .gitlab-ci.yml when
// present and walks the .gitlab-ci/ directory tree for any *.yml/*.yaml.
func (g *GitLabClient) LoadWorkflows(ctx context.Context, token string, repo RepoCoord, ref string) ([]WorkflowFile, error) {
	if repo.ID == "" {
		return nil, errors.New("gitlab: project id required for LoadWorkflows")
	}
	host := g.hostForRepo(repo)
	if ref == "" {
		ref = "HEAD"
	}

	var files []WorkflowFile

	// Root .gitlab-ci.yml (404 = no CI config, not an error).
	if content, ok, err := g.fetchProjectFile(ctx, token, host, repo.ID, ".gitlab-ci.yml", ref); err != nil {
		return nil, err
	} else if ok {
		files = append(files, WorkflowFile{Path: ".gitlab-ci.yml", Content: content})
	}

	// .gitlab-ci/ directory tree — walk via /repository/tree.
	type treeEntry struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Path string `json:"path"`
	}
	for page := 1; ; page++ {
		u := fmt.Sprintf("%s/projects/%s/repository/tree?ref=%s&path=.gitlab-ci&recursive=true&per_page=100&page=%d",
			g.api(host), url.PathEscape(repo.ID), url.QueryEscape(ref), page)
		var batch []treeEntry
		err := g.do(ctx, http.MethodGet, u, token, nil, &batch)
		if err != nil {
			// 404 = .gitlab-ci/ doesn't exist; that's fine.
			if StatusOf(err) == http.StatusNotFound {
				break
			}
			return nil, err
		}
		for _, e := range batch {
			if e.Type != "blob" {
				continue
			}
			lower := strings.ToLower(e.Path)
			if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
				continue
			}
			content, ok, err := g.fetchProjectFile(ctx, token, host, repo.ID, e.Path, ref)
			if err != nil {
				return nil, err
			}
			if ok {
				files = append(files, WorkflowFile{Path: e.Path, Content: content})
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	return files, nil
}

// LoadRepoConfig implements VCSClient. Fetches the first present .pipefort.yml
// candidate from the project root at the given ref, or (nil, nil) when absent.
func (g *GitLabClient) LoadRepoConfig(ctx context.Context, token string, repo RepoCoord, ref string) ([]byte, error) {
	if repo.ID == "" {
		return nil, nil
	}
	host := g.hostForRepo(repo)
	if ref == "" {
		ref = "HEAD"
	}
	for _, name := range scanner.ConfigFileNames() {
		content, ok, err := g.fetchProjectFile(ctx, token, host, repo.ID, name, ref)
		if err != nil {
			return nil, err
		}
		if ok {
			return content, nil
		}
	}
	return nil, nil
}

// fetchProjectFile downloads a single file from a project at the given ref.
// Returns (nil, false, nil) on 404 so callers can treat "absent" cleanly.
func (g *GitLabClient) fetchProjectFile(ctx context.Context, token, host, projectID, path, ref string) ([]byte, bool, error) {
	u := fmt.Sprintf("%s/projects/%s/repository/files/%s/raw?ref=%s",
		g.api(host), url.PathEscape(projectID), url.PathEscape(path), url.QueryEscape(ref))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("PRIVATE-TOKEN", token) // GitLab also accepts Authorization: Bearer.
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "Pipefort")
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, &GitLabAPIError{Method: http.MethodGet, URL: u, Status: resp.StatusCode, Body: string(body)}
	}
	return body, true, nil
}

// hostForRepo derives the API host for a RepoCoord. In v1 the host comes
// from the installation row by way of the handler; if callers don't thread
// it, we fall back to the configured default. (Section 6 ensures handlers
// thread the host via auth.Host through to LoadWorkflows.)
func (g *GitLabClient) hostForRepo(_ RepoCoord) string {
	host := g.defaultHost
	if host == "" {
		host = "gitlab.com"
	}
	return host
}

// AuditSettings implements VCSClient. It fetches the GitLab project's
// configuration (merge policy, pipeline visibility, protected default branch,
// approvals) and runs the GitLab settings scanner over it.
func (g *GitLabClient) AuditSettings(ctx context.Context, token string, repo RepoCoord, defaultBranch, htmlURL string) ([]scanner.Finding, error) {
	pc, err := g.FetchProjectSettings(ctx, token, repo, defaultBranch, htmlURL)
	if err != nil {
		return nil, err
	}
	return scanner.ScanGitLabProjectSettings(*pc), nil
}

// FetchProjectSettings reads the GitLab project's configuration into a
// scanner.GitLabProjectContext. Approvals (Premium) and protected-branch reads
// degrade gracefully — a 404/403 leaves the corresponding fields nil/unfetched
// rather than failing the whole audit.
func (g *GitLabClient) FetchProjectSettings(ctx context.Context, token string, repo RepoCoord, defaultBranch, htmlURL string) (*scanner.GitLabProjectContext, error) {
	if repo.ID == "" {
		return nil, errors.New("gitlab: project id required for settings audit")
	}
	host := g.hostForRepo(repo)
	pc := &scanner.GitLabProjectContext{
		ProjectPath:   repo.Owner + "/" + repo.Name,
		WebURL:        htmlURL,
		DefaultBranch: defaultBranch,
	}

	// GET /projects/:id — merge policy, public pipelines, default branch.
	var proj struct {
		DefaultBranch                    string `json:"default_branch"`
		OnlyAllowMergeIfPipelineSucceeds *bool  `json:"only_allow_merge_if_pipeline_succeeds"`
		PublicBuilds                     *bool  `json:"public_jobs"`
	}
	if err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/projects/%s", g.api(host), url.PathEscape(repo.ID)), token, nil, &proj); err != nil {
		return nil, err
	}
	if proj.DefaultBranch != "" {
		pc.DefaultBranch = proj.DefaultBranch
	}
	pc.OnlyAllowMergeIfPipelineSucceeds = proj.OnlyAllowMergeIfPipelineSucceeds
	pc.PublicBuilds = proj.PublicBuilds

	// GET /projects/:id/protected_branches — is the default branch protected,
	// and does it allow force push? A 403/404 leaves BranchProtectionFetched
	// false so the rules are skipped rather than false-firing.
	var protected []struct {
		Name           string `json:"name"`
		AllowForcePush bool   `json:"allow_force_push"`
	}
	if err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/projects/%s/protected_branches?per_page=100", g.api(host), url.PathEscape(repo.ID)), token, nil, &protected); err == nil {
		pc.BranchProtectionFetched = true
		for _, b := range protected {
			if b.Name == pc.DefaultBranch || b.Name == "*" {
				pc.DefaultBranchProtected = true
				pc.DefaultBranchAllowsForcePush = b.AllowForcePush
				break
			}
		}
	}

	// GET /projects/:id/approvals — approvals_before_merge (Premium). 404/403
	// on Free tier: leave ApprovalsBeforeMerge nil so the rule is skipped.
	var approvals struct {
		ApprovalsBeforeMerge *int `json:"approvals_before_merge"`
	}
	if err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/projects/%s/approvals", g.api(host), url.PathEscape(repo.ID)), token, nil, &approvals); err == nil {
		pc.ApprovalsBeforeMerge = approvals.ApprovalsBeforeMerge
	}

	return pc, nil
}

// FixSetting implements VCSClient for the two project-level settings that are
// safe to toggle via the projects API: enabling "pipelines must succeed" and
// disabling public pipelines. Protected-branch and approval fixes are left for
// manual remediation. dryRun reports the action without writing.
func (g *GitLabClient) FixSetting(ctx context.Context, token string, repo RepoCoord, _ string, ruleID scanner.RuleID, dryRun bool) (SettingsFixAction, error) {
	host := g.hostForRepo(repo)
	var field, desc string
	body := map[string]any{}
	switch ruleID {
	case scanner.RuleGitLabMergeNoPipeline:
		field, desc = "only_allow_merge_if_pipeline_succeeds", "Enable 'Pipelines must succeed' for merge requests"
		body[field] = true
	case scanner.RuleGitLabPublicPipelines:
		field, desc = "public_jobs", "Disable public pipelines (hide job logs/artifacts from non-members)"
		body[field] = false
	default:
		return SettingsFixAction{}, ErrSettingsNotSupported
	}
	action := SettingsFixAction{RuleID: ruleID, Description: desc, Endpoint: "PUT /projects/:id"}
	if dryRun {
		return action, nil
	}
	err := g.do(ctx, http.MethodPut, fmt.Sprintf("%s/projects/%s", g.api(host), url.PathEscape(repo.ID)), token, mustJSON(body), nil)
	if err != nil {
		return SettingsFixAction{}, err
	}
	return action, nil
}

// FixWorkflow implements VCSClient — the 5-step MR-based remediation pipeline.
// Mirrors the GitHub PR pipeline in workflow_fixer.go.
func (g *GitLabClient) FixWorkflow(ctx context.Context, token string, repo RepoCoord, defaultBranch, filePath string, ruleID scanner.RuleID) (ChangeRequestResult, error) {
	res := ChangeRequestResult{Provider: ProviderGitLab, RuleID: ruleID, File: filePath}
	if !IsAutoFixableWorkflowRule(ruleID) {
		return res, fmt.Errorf("rule %s has no workflow auto-fix", ruleID)
	}
	if defaultBranch == "" {
		defaultBranch = "main"
	}
	if repo.ID == "" {
		return res, errors.New("gitlab: project id required for FixWorkflow")
	}
	host := g.hostForRepo(repo)

	// 1. Fetch the file's current bytes.
	current, ok, err := g.fetchProjectFile(ctx, token, host, repo.ID, filePath, defaultBranch)
	if err != nil {
		return res, fmt.Errorf("fetch %s: %w", filePath, err)
	}
	if !ok {
		return res, fmt.Errorf("file %s not found on %s", filePath, defaultBranch)
	}

	// 2. Re-scan + apply the fixer.
	fresh, err := scanner.ScanBytes(filePath, current)
	if err != nil {
		return res, fmt.Errorf("scan %s: %w", filePath, err)
	}
	scoped := scopedFindings(fresh, ruleID, filePath)
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

	// 3. Ensure the deterministic fix branch exists.
	branchName := ChangeBranchName(ruleID, filePath)
	res.BranchName = branchName
	if err := g.ensureBranch(ctx, token, host, repo.ID, defaultBranch, branchName); err != nil {
		return res, fmt.Errorf("ensure branch %s: %w", branchName, err)
	}

	// 4. Commit the rewritten file to the branch. Try "update"; if the file
	// doesn't exist on the branch yet (e.g. the branch was reused after the
	// file moved on default), retry once with "create".
	if err := g.commitToBranch(ctx, token, host, repo.ID, branchName, filePath, newContent, ruleID, "update"); err != nil {
		if gitlabIsFileNotFound(err) {
			if err2 := g.commitToBranch(ctx, token, host, repo.ID, branchName, filePath, newContent, ruleID, "create"); err2 != nil {
				return res, fmt.Errorf("commit %s on %s: %w", filePath, branchName, err2)
			}
		} else {
			return res, fmt.Errorf("commit %s on %s: %w", filePath, branchName, err)
		}
	}

	// 5. Open the MR (or reuse the existing open one for this source branch).
	mrURL, mrIID, reused, err := g.openOrReuseMR(ctx, token, host, repo.ID, defaultBranch, branchName, ruleID, filePath, fixesCount)
	if err != nil {
		return res, fmt.Errorf("open MR: %w", err)
	}
	res.URL = mrURL
	res.Number = mrIID
	res.Reused = reused
	return res, nil
}

// ensureBranch creates a branch from default_branch on the project. GitLab
// returns 400 with "Branch already exists" when the ref is already present —
// we treat that as idempotent.
func (g *GitLabClient) ensureBranch(ctx context.Context, token, host, projectID, baseBranch, newBranch string) error {
	u := fmt.Sprintf("%s/projects/%s/repository/branches?branch=%s&ref=%s",
		g.api(host), url.PathEscape(projectID), url.QueryEscape(newBranch), url.QueryEscape(baseBranch))
	err := g.do(ctx, http.MethodPost, u, token, nil, nil)
	if err == nil {
		return nil
	}
	if gitlabIsBranchExists(err) {
		return nil
	}
	return err
}

// commitToBranch posts a single-file commit. action is "update" or "create".
func (g *GitLabClient) commitToBranch(ctx context.Context, token, host, projectID, branch, filePath string, content []byte, ruleID scanner.RuleID, action string) error {
	u := fmt.Sprintf("%s/projects/%s/repository/commits", g.api(host), url.PathEscape(projectID))
	body := map[string]any{
		"branch":         branch,
		"commit_message": ChangeCommitMessage(ruleID, filePath),
		"actions": []map[string]string{{
			"action":    action,
			"file_path": filePath,
			"content":   string(content),
		}},
	}
	return g.do(ctx, http.MethodPost, u, token, mustJSON(body), nil)
}

// openOrReuseMR opens a merge request from source→target; if GitLab reports
// an existing MR for the source branch, look it up and return that instead.
func (g *GitLabClient) openOrReuseMR(ctx context.Context, token, host, projectID, targetBranch, sourceBranch string, ruleID scanner.RuleID, filePath string, fixesCount int) (string, int, bool, error) {
	create := map[string]any{
		"source_branch":        sourceBranch,
		"target_branch":        targetBranch,
		"title":                ChangeRequestTitle(ruleID),
		"description":          ChangeRequestBody(ruleID, filePath, fixesCount),
		"remove_source_branch": true,
	}
	u := fmt.Sprintf("%s/projects/%s/merge_requests", g.api(host), url.PathEscape(projectID))
	var resp struct {
		IID    int    `json:"iid"`
		WebURL string `json:"web_url"`
	}
	err := g.do(ctx, http.MethodPost, u, token, mustJSON(create), &resp)
	if err == nil {
		return resp.WebURL, resp.IID, false, nil
	}
	if !gitlabIsMRExists(err) {
		return "", 0, false, err
	}
	// Look up the existing open MR for this source branch.
	listURL := fmt.Sprintf("%s/projects/%s/merge_requests?state=opened&source_branch=%s",
		g.api(host), url.PathEscape(projectID), url.QueryEscape(sourceBranch))
	var list []struct {
		IID    int    `json:"iid"`
		WebURL string `json:"web_url"`
	}
	if listErr := g.do(ctx, http.MethodGet, listURL, token, nil, &list); listErr != nil {
		return "", 0, false, fmt.Errorf("create MR failed (%v) and lookup failed: %w", err, listErr)
	}
	if len(list) == 0 {
		return "", 0, false, fmt.Errorf("create MR failed (%v) and lookup found no open MR", err)
	}
	return list[0].WebURL, list[0].IID, true, nil
}

// --- Low-level HTTP --------------------------------------------------------

// GitLabAPIError mirrors *GitHubAPIError so callers can branch on status via
// StatusOf().
type GitLabAPIError struct {
	Method string
	URL    string
	Status int
	Body   string
}

func (e *GitLabAPIError) Error() string {
	return fmt.Sprintf("gitlab %s %s: status %d: %s", e.Method, e.URL, e.Status, truncate(e.Body, 300))
}

// gitlabIsBranchExists reports whether the error is GitLab's idempotent
// "Branch already exists" 400.
func gitlabIsBranchExists(err error) bool {
	var apiErr *GitLabAPIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Status != http.StatusBadRequest {
		return false
	}
	return strings.Contains(strings.ToLower(apiErr.Body), "branch already exists")
}

func gitlabIsFileNotFound(err error) bool {
	var apiErr *GitLabAPIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Status != http.StatusBadRequest {
		return false
	}
	low := strings.ToLower(apiErr.Body)
	return strings.Contains(low, "file with this name doesn") || strings.Contains(low, "a file with this name does not exist")
}

func gitlabIsMRExists(err error) bool {
	var apiErr *GitLabAPIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Status != http.StatusConflict && apiErr.Status != http.StatusBadRequest {
		return false
	}
	low := strings.ToLower(apiErr.Body)
	return strings.Contains(low, "another open merge request already exists")
}

// do runs a GitLab API request with the standard headers and decodes JSON
// into out. Non-2xx returns a *GitLabAPIError so callers can branch on status.
func (g *GitLabClient) do(ctx context.Context, method, u, bearer string, body io.Reader, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("PRIVATE-TOKEN", bearer)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Pipefort")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &GitLabAPIError{Method: method, URL: u, Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// mustJSON wraps body into a *bytes.Reader; panics only on json.Marshal of
// an unmarshallable value (map[string]any of strings/bools/ints — safe).
func mustJSON(v any) io.Reader {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // map[string]any constructed inline never fails to marshal here
	}
	return bytes.NewReader(b)
}
