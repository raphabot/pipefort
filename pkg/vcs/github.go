package vcs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/raphabot/pipefort/pkg/scanner"
)

const githubAPI = "https://api.github.com"

// GitHubClient talks to the GitHub REST API on behalf of a GitHub App.
type GitHubClient struct {
	appID      string
	privateKey *rsaKey
	http       *http.Client
	baseURL    string // overridable in tests; defaults to githubAPI
}

// NewGitHubAppClient parses the app's PEM private key once at construction.
// When GitHub App creds are not configured (empty privateKeyPEM) the client is
// still returned (so the server can boot); its calls fail with a clear error
// until creds are set.
func NewGitHubAppClient(appID, privateKeyPEM string, opts ...Option) (*GitHubClient, error) {
	o := newClientOptions(opts)
	c := &GitHubClient{
		appID:   appID,
		http:    &http.Client{Timeout: 20 * time.Second},
		baseURL: githubAPI,
	}
	applyGitHubOptions(c, o)
	if strings.TrimSpace(privateKeyPEM) == "" {
		return c, nil
	}
	key, err := parseRSAKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub App private key: %w", err)
	}
	c.privateKey = key
	return c, nil
}

// NewBareGitHubClient builds a GitHub client that never mints App JWTs — it
// can only call endpoints that accept a pre-obtained token (a user PAT or
// `gh auth token` output). The CLI uses this for repository-settings audits;
// the web app keeps using NewGitHubAppClient with the GitHub App.
func NewBareGitHubClient(opts ...Option) *GitHubClient {
	c := &GitHubClient{
		http:    &http.Client{Timeout: 20 * time.Second},
		baseURL: githubAPI,
	}
	applyGitHubOptions(c, newClientOptions(opts))
	return c
}

func applyGitHubOptions(c *GitHubClient, o clientOptions) {
	if o.baseURL != "" {
		c.baseURL = o.baseURL
	}
	if o.httpClient != nil {
		c.http = o.httpClient
	}
}

// api returns the configured base URL, falling back to the public API.
func (g *GitHubClient) api() string {
	if g.baseURL != "" {
		return g.baseURL
	}
	return githubAPI
}

// appJWT mints a short-lived (10 min) RS256 JWT identifying the App itself.
func (g *GitHubClient) appJWT() (string, error) {
	if g.privateKey == nil {
		return "", fmt.Errorf("GitHub App is not configured (set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY)")
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    g.appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)), // clock skew slack
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(g.privateKey.key)
}

// InstallationToken exchanges the app JWT for a short-lived installation token
// scoped to one installation's repositories.
func (g *GitHubClient) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	appTok, err := g.appJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", g.api(), installationID)
	var out struct {
		Token string `json:"token"`
	}
	if err := g.do(ctx, http.MethodPost, url, appTok, nil, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty installation token")
	}
	return out.Token, nil
}

// Installation describes the account an app is installed on.
type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login     string `json:"login"`
		Type      string `json:"type"`
		AvatarURL string `json:"avatar_url"`
	} `json:"account"`
}

// GetInstallation fetches metadata for one installation (account login/type).
func (g *GitHubClient) GetInstallation(ctx context.Context, installationID int64) (*Installation, error) {
	appTok, err := g.appJWT()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/app/installations/%d", g.api(), installationID)
	var inst Installation
	if err := g.do(ctx, http.MethodGet, url, appTok, nil, &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

// Repo is the subset of repository metadata we persist.
type Repo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// ListRepos returns every repository the installation can access, following
// pagination.
func (g *GitHubClient) ListRepos(ctx context.Context, token string) ([]Repo, error) {
	var repos []Repo
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s/installation/repositories?per_page=100&page=%d", g.api(), page)
		var out struct {
			TotalCount   int    `json:"total_count"`
			Repositories []Repo `json:"repositories"`
		}
		if err := g.do(ctx, http.MethodGet, url, token, nil, &out); err != nil {
			return nil, err
		}
		repos = append(repos, out.Repositories...)
		if len(out.Repositories) < 100 {
			break
		}
	}
	return repos, nil
}

// ListOwnerRepos lists a GitHub owner's repositories by public listing, trying
// the org endpoint first and falling back to the user endpoint (the owner may
// be either). Paginated. Used by the CLI org-wide scan, which authenticates
// with a PAT rather than an installation.
func (g *GitHubClient) ListOwnerRepos(ctx context.Context, token, owner string) ([]Repo, error) {
	for _, kind := range []string{"orgs", "users"} {
		var repos []Repo
		var notFound bool
		for page := 1; ; page++ {
			url := fmt.Sprintf("%s/%s/%s/repos?per_page=100&page=%d&type=all", g.api(), kind, owner, page)
			var out []Repo
			if err := g.do(ctx, http.MethodGet, url, token, nil, &out); err != nil {
				if StatusOf(err) == http.StatusNotFound {
					notFound = true
					break
				}
				return nil, err
			}
			repos = append(repos, out...)
			if len(out) < 100 {
				break
			}
		}
		if notFound {
			continue // try the next owner kind
		}
		return repos, nil
	}
	return nil, fmt.Errorf("owner %q not found as a GitHub organization or user", owner)
}

// ListPullRequestFiles returns the paths changed in a pull request (paginated).
// Used to skip the whole PR check when no workflow files were touched.
func (g *GitHubClient) ListPullRequestFiles(ctx context.Context, token, owner, repo string, number int) ([]string, error) {
	var files []string
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=100&page=%d", g.api(), owner, repo, number, page)
		var out []struct {
			Filename string `json:"filename"`
		}
		if err := g.do(ctx, http.MethodGet, url, token, nil, &out); err != nil {
			return nil, err
		}
		for _, f := range out {
			files = append(files, f.Filename)
		}
		if len(out) < 100 {
			break
		}
	}
	return files, nil
}

// CheckRunAnnotation is one inline annotation on a Check Run. Level is
// "failure" | "warning" | "notice".
type CheckRunAnnotation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Level     string `json:"annotation_level"`
	Message   string `json:"message"`
	Title     string `json:"title,omitempty"`
}

// CheckRunParams is the payload for creating a completed Check Run.
type CheckRunParams struct {
	Name        string
	HeadSHA     string
	Conclusion  string // "success" | "failure" | "neutral"
	Title       string
	Summary     string
	Annotations []CheckRunAnnotation
}

// CreateCheckRun posts a completed Check Run for a commit. GitHub accepts at
// most 50 annotations per request; callers must pre-truncate. Requires the App
// to hold the `checks: write` permission.
func (g *GitHubClient) CreateCheckRun(ctx context.Context, token, owner, repo string, p CheckRunParams) error {
	if p.Annotations == nil {
		p.Annotations = []CheckRunAnnotation{}
	}
	body := map[string]any{
		"name":       p.Name,
		"head_sha":   p.HeadSHA,
		"status":     "completed",
		"conclusion": p.Conclusion,
		"output": map[string]any{
			"title":       p.Title,
			"summary":     p.Summary,
			"annotations": p.Annotations,
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/repos/%s/%s/check-runs", g.api(), owner, repo)
	return g.do(ctx, http.MethodPost, url, token, bytes.NewReader(buf), nil)
}

// WorkflowFile is a single fetched workflow with its raw bytes.
type WorkflowFile struct {
	Path    string
	Content []byte
}

type treeResponse struct {
	Tree []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
		Size int    `json:"size"`
	} `json:"tree"`
}

// FetchWorkflows lists .github/workflows/*.yml|yaml via the Git Trees API and
// downloads each file's bytes. No clone required, so this is fast and fits a
// serverless time budget.
func (g *GitHubClient) FetchWorkflows(ctx context.Context, token, owner, repo, ref string) ([]WorkflowFile, error) {
	files, _, err := g.FetchWorkflowsLimited(ctx, token, owner, repo, ref, 0, 0)
	return files, err
}

// FetchWorkflowsLimited is FetchWorkflows with abuse caps for the anonymous public
// scan: maxFiles bounds how many workflow blobs are downloaded (0 = unlimited;
// truncated reports whether the cap was hit) and maxBlobBytes skips oversized
// blobs (0 = unlimited).
func (g *GitHubClient) FetchWorkflowsLimited(ctx context.Context, token, owner, repo, ref string, maxFiles, maxBlobBytes int) (files []WorkflowFile, truncated bool, err error) {
	if ref == "" {
		ref = "HEAD"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", g.api(), owner, repo, ref)
	var tree treeResponse
	if err := g.do(ctx, http.MethodGet, url, token, nil, &tree); err != nil {
		// A repo with no commits / no tree returns 404/409; treat as "no workflows".
		if strings.Contains(err.Error(), "status 404") || strings.Contains(err.Error(), "status 409") {
			return nil, false, nil
		}
		return nil, false, err
	}

	for _, node := range tree.Tree {
		if node.Type != "blob" || !isWorkflowPath(node.Path) {
			continue
		}
		if maxBlobBytes > 0 && node.Size > maxBlobBytes {
			continue
		}
		if maxFiles > 0 && len(files) >= maxFiles {
			return files, true, nil
		}
		content, err := g.fetchBlob(ctx, token, owner, repo, node.SHA)
		if err != nil {
			return nil, false, fmt.Errorf("fetch %s: %w", node.Path, err)
		}
		files = append(files, WorkflowFile{Path: node.Path, Content: content})
	}
	return files, false, nil
}

// RepoMeta is the subset of GET /repos/{owner}/{repo} the public teaser scan
// needs: canonical naming, the branch to scan, and the private flag that gates
// anonymous access.
type RepoMeta struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
}

// FetchRepoMeta fetches repository metadata. The public scan uses it to
// distinguish "repo missing" from "repo has no workflows" (the trees API
// returns 404 for both) and to refuse private repos before spending any
// further API calls.
func (g *GitHubClient) FetchRepoMeta(ctx context.Context, token, owner, repo string) (*RepoMeta, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", g.api(), owner, repo)
	var meta RepoMeta
	if err := g.do(ctx, http.MethodGet, url, token, nil, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// FetchRepoConfig fetches the raw .pipefort.yml config bytes via the GitHub
// contents API, trying each candidate filename in precedence order. Returns
// (nil, nil) when no config file exists (a 404 on every candidate).
func (g *GitHubClient) FetchRepoConfig(ctx context.Context, token, owner, repo, ref string) ([]byte, error) {
	for _, name := range scanner.ConfigFileNames() {
		url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", g.api(), owner, repo, name)
		if ref != "" {
			url += "?ref=" + ref
		}
		var out struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		if err := g.do(ctx, http.MethodGet, url, token, nil, &out); err != nil {
			if StatusOf(err) == http.StatusNotFound {
				continue
			}
			return nil, err
		}
		if out.Encoding == "base64" {
			clean := strings.ReplaceAll(out.Content, "\n", "")
			return base64.StdEncoding.DecodeString(clean)
		}
		return []byte(out.Content), nil
	}
	return nil, nil
}

// IsWorkflowPath reports whether p is a GitHub Actions workflow file
// (.github/workflows/*.yml|yaml). Exported for the PR-check path in pkg/api.
func IsWorkflowPath(p string) bool { return isWorkflowPath(p) }

func isWorkflowPath(p string) bool {
	if !strings.HasPrefix(p, ".github/workflows/") {
		return false
	}
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// fetchBlob downloads and base64-decodes a single git blob.
func (g *GitHubClient) fetchBlob(ctx context.Context, token, owner, repo, sha string) ([]byte, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/blobs/%s", g.api(), owner, repo, sha)
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := g.do(ctx, http.MethodGet, url, token, nil, &out); err != nil {
		return nil, err
	}
	if out.Encoding == "base64" {
		// GitHub wraps base64 content at 60 cols.
		clean := strings.ReplaceAll(out.Content, "\n", "")
		return base64.StdEncoding.DecodeString(clean)
	}
	return []byte(out.Content), nil
}

// GitHubAPIError is returned by do() (and therefore wraps every non-2xx
// response) so callers can distinguish "not found" from other failures via
// errors.As, while the .Error() string format stays identical to the legacy
// `github METHOD URL: status N: BODY` shape that older callers grep with
// strings.Contains.
type GitHubAPIError struct {
	Method string
	URL    string
	Status int
	Body   string
}

func (e *GitHubAPIError) Error() string {
	return fmt.Sprintf("github %s %s: status %d: %s", e.Method, e.URL, e.Status, truncate(e.Body, 300))
}

// StatusOf reports the HTTP status code if err wraps a provider API error
// (*GitHubAPIError or *GitLabAPIError), else 0.
func StatusOf(err error) int {
	var ghErr *GitHubAPIError
	if errors.As(err, &ghErr) {
		return ghErr.Status
	}
	var glErr *GitLabAPIError
	if errors.As(err, &glErr) {
		return glErr.Status
	}
	return 0
}

// branchProtectionUnavailable reports whether err is GitHub's 403 for the
// "Get branch protection" endpoint that means the feature is unavailable on
// this repository's *plan* — not that the token lacks permission. GitHub
// returns `403 {"message":"Upgrade to GitHub Pro or make this repository
// public to enable this feature."}` for protected branches on private repos
// under a free plan. We treat that as "no branch protection" rather than a
// permission-degrade so the rest of the settings audit still runs.
func branchProtectionUnavailable(err error) bool {
	var ghErr *GitHubAPIError
	if !errors.As(err, &ghErr) || ghErr.Status != http.StatusForbidden {
		return false
	}
	body := strings.ToLower(ghErr.Body)
	return strings.Contains(body, "upgrade to github") ||
		strings.Contains(body, "make this repository public")
}

// do performs a GitHub API request with the standard headers and decodes the
// JSON body into out (if non-nil). Returns a *GitHubAPIError on non-2xx so
// callers can switch on the status code via StatusOf().
func (g *GitHubClient) do(ctx context.Context, method, url, bearer string, body io.Reader, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "Pipefort")

	resp, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &GitHubAPIError{Method: method, URL: url, Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// codeownersPaths is the precedence order GitHub itself uses when picking up a
// CODEOWNERS file.
var codeownersPaths = []string{"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}

// FetchRepositorySettings issues the handful of GitHub API calls the
// repository-settings audit (pkg/scanner) needs and assembles the result. Each
// non-fatal 404 maps to a zero/false sentinel so callers can keep auditing
// even when one feature is unavailable; a 403 or any other status is returned
// as a *GitHubAPIError so the caller can surface a permission-degrade hint.
//
// htmlURL is the repo's https://github.com/{owner}/{repo} URL — used only to
// build human remediation links in findings; pass "" if unknown.
func (g *GitHubClient) FetchRepositorySettings(ctx context.Context, token, owner, repo, defaultBranch, htmlURL string) (*scanner.RepositoryContext, error) {
	rc := &scanner.RepositoryContext{
		Owner:         owner,
		Repo:          repo,
		DefaultBranch: defaultBranch,
		HTMLURL:       htmlURL,
	}

	// 1. Repo metadata (always required; surfaces security_and_analysis).
	rc.Repository = &scanner.RepoInfo{}
	if err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/%s", g.api(), owner, repo), token, nil, rc.Repository); err != nil {
		return nil, fmt.Errorf("fetch repo: %w", err)
	}
	if rc.DefaultBranch == "" {
		rc.DefaultBranch = rc.Repository.DefaultBranch
	}

	// 2. Branch protection on the default branch — 404 means "no protection".
	bp := &scanner.BranchProtection{}
	bpErr := g.do(ctx, http.MethodGet,
		fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection", g.api(), owner, repo, rc.DefaultBranch),
		token, nil, bp)
	switch {
	case bpErr == nil:
		rc.BranchProtection = bp
	case StatusOf(bpErr) == http.StatusNotFound:
		rc.BranchProtection = nil
	case branchProtectionUnavailable(bpErr):
		// Private repo on a plan without protected branches — the token has the
		// permission, GitHub just won't serve the feature. Flag it so the audit
		// reports it honestly instead of as a missing-protection or
		// missing-permission problem, then keep auditing everything else.
		rc.BranchProtection = nil
		rc.BranchProtectionUnavailable = true
	default:
		return nil, fmt.Errorf("fetch branch protection: %w", bpErr)
	}

	// 3. Default workflow permissions — 404 means Actions is disabled here.
	wp := &scanner.WorkflowPermissions{}
	wpErr := g.do(ctx, http.MethodGet,
		fmt.Sprintf("%s/repos/%s/%s/actions/permissions/workflow", g.api(), owner, repo),
		token, nil, wp)
	switch {
	case wpErr == nil:
		rc.WorkflowPerms = wp
	case StatusOf(wpErr) == http.StatusNotFound:
		rc.WorkflowPerms = nil
	default:
		return nil, fmt.Errorf("fetch workflow permissions: %w", wpErr)
	}

	// 4. Actions allowlist (enabled? all/local_only/selected?).
	ap := &scanner.ActionsPermissions{}
	apErr := g.do(ctx, http.MethodGet,
		fmt.Sprintf("%s/repos/%s/%s/actions/permissions", g.api(), owner, repo),
		token, nil, ap)
	switch {
	case apErr == nil:
		rc.ActionsPolicy = ap
	case StatusOf(apErr) == http.StatusNotFound:
		rc.ActionsPolicy = nil
	default:
		return nil, fmt.Errorf("fetch actions permissions: %w", apErr)
	}

	// 5. Dependabot vulnerability alerts: 204 = enabled, 404 = disabled.
	vaErr := g.do(ctx, http.MethodGet,
		fmt.Sprintf("%s/repos/%s/%s/vulnerability-alerts", g.api(), owner, repo),
		token, nil, nil)
	switch {
	case vaErr == nil:
		rc.DependabotAlerts = true
	case StatusOf(vaErr) == http.StatusNotFound:
		rc.DependabotAlerts = false
	default:
		return nil, fmt.Errorf("fetch dependabot alerts: %w", vaErr)
	}

	// 6. CODEOWNERS presence — try each canonical location, stop at the first hit.
	for _, p := range codeownersPaths {
		err := g.do(ctx, http.MethodGet,
			fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s", g.api(), owner, repo, p, rc.DefaultBranch),
			token, nil, nil)
		if err == nil {
			rc.HasCodeowners = true
			break
		}
		if StatusOf(err) != http.StatusNotFound {
			return nil, fmt.Errorf("check CODEOWNERS at %s: %w", p, err)
		}
	}

	return rc, nil
}
