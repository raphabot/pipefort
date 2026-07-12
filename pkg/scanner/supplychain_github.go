package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHubPinAuditor implements PinAuditor against api.github.com. A token is
// optional but strongly recommended — anonymous requests share a 60/hour limit.
// It reuses the package's githubAPIBaseURL var so tests can point it at an
// httptest server.
type GitHubPinAuditor struct {
	Token  string
	Client *http.Client
}

// NewGitHubPinAuditor builds an auditor with a 10s-per-request HTTP client.
func NewGitHubPinAuditor(token string) *GitHubPinAuditor {
	return &GitHubPinAuditor{
		Token:  token,
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (g *GitHubPinAuditor) do(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pipefort-audit-pins")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	return g.Client.Do(req)
}

// ResolveRef resolves a tag/branch/SHA to its commit SHA via the commits API.
// A 404 means the ref/SHA isn't present in the repo (found=false).
func (g *GitHubPinAuditor) ResolveRef(ctx context.Context, owner, repo, ref string) (string, bool, error) {
	resp, err := g.do(ctx, fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, url.PathEscape(ref)))
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			SHA string `json:"sha"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return "", false, err
		}
		return body.SHA, true, nil
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("github commits API: %s", resp.Status)
	}
}

// Advisories returns GHSA entries affecting an action via the global advisories
// API, filtered to the actions ecosystem and this package.
func (g *GitHubPinAuditor) Advisories(ctx context.Context, owner, repo string) ([]Advisory, error) {
	pkg := owner + "/" + repo
	q := url.Values{}
	q.Set("ecosystem", "actions")
	q.Set("affects", pkg)
	resp, err := g.do(ctx, "/advisories?"+q.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github advisories API: %s", resp.Status)
	}

	var raw []struct {
		GHSAID          string `json:"ghsa_id"`
		Summary         string `json:"summary"`
		Vulnerabilities []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			VulnerableRange string          `json:"vulnerable_version_range"`
			FirstPatched    json.RawMessage `json:"first_patched_version"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	var out []Advisory
	for _, a := range raw {
		for _, v := range a.Vulnerabilities {
			// Only consider the matching actions package (the API filters by
			// affects, but an advisory can list several packages).
			if !strings.EqualFold(v.Package.Ecosystem, "actions") || !strings.EqualFold(v.Package.Name, pkg) {
				continue
			}
			out = append(out, Advisory{
				GHSAID:          a.GHSAID,
				Summary:         a.Summary,
				VulnerableRange: v.VulnerableRange,
				FirstPatched:    parseFirstPatched(v.FirstPatched),
			})
		}
	}
	return out, nil
}

// RepoArchived reports whether owner/repo is archived via the repo API.
func (g *GitHubPinAuditor) RepoArchived(ctx context.Context, owner, repo string) (bool, bool, error) {
	resp, err := g.do(ctx, fmt.Sprintf("/repos/%s/%s", owner, repo))
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			Archived bool `json:"archived"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return false, false, err
		}
		return body.Archived, true, nil
	case http.StatusNotFound:
		return false, false, nil
	default:
		return false, false, fmt.Errorf("github repo API: %s", resp.Status)
	}
}

// RefKinds reports whether ref exists as a branch and/or a tag via the git refs
// API. A 404 on a kind means that kind doesn't exist.
func (g *GitHubPinAuditor) RefKinds(ctx context.Context, owner, repo, ref string) (bool, bool, error) {
	exists := func(kind string) (bool, error) {
		resp, err := g.do(ctx, fmt.Sprintf("/repos/%s/%s/git/ref/%s/%s", owner, repo, kind, url.PathEscape(ref)))
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			return true, nil
		case http.StatusNotFound:
			return false, nil
		default:
			return false, fmt.Errorf("github refs API: %s", resp.Status)
		}
	}
	isBranch, err := exists("heads")
	if err != nil {
		return false, false, err
	}
	isTag, err := exists("tags")
	if err != nil {
		return false, false, err
	}
	return isBranch, isTag, nil
}

// TagSHAs returns the commit SHAs the repo's tags point at (first page only —
// enough for the stale-ref heuristic; older tags rarely matter).
func (g *GitHubPinAuditor) TagSHAs(ctx context.Context, owner, repo string) ([]string, error) {
	resp, err := g.do(ctx, fmt.Sprintf("/repos/%s/%s/tags?per_page=100", owner, repo))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github tags API: %s", resp.Status)
	}
	var raw []struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		if t.Commit.SHA != "" {
			out = append(out, t.Commit.SHA)
		}
	}
	return out, nil
}

// parseFirstPatched tolerates both shapes GitHub has used for
// first_patched_version: a bare string and an object with an `identifier`.
func parseFirstPatched(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Identifier
	}
	return ""
}
