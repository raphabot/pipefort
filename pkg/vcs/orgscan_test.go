package vcs

import (
	"context"
	"strings"
	"testing"

	"github.com/raphabot/pipefort/pkg/scanner"
)

func TestOrgScanAggregatesRepos(t *testing.T) {
	gh := newMockGitHub(t)
	// Two repos owned by "acme"; the shared tree/blob means both scan the same
	// vulnerable workflow (enough to prove aggregation + path prefixing).
	gh.ownerRepos = []Repo{
		{Name: "web", FullName: "acme/web", DefaultBranch: "main", Owner: struct {
			Login string `json:"login"`
		}{Login: "acme"}},
		{Name: "api", FullName: "acme/api", DefaultBranch: "main", Owner: struct {
			Login string `json:"login"`
		}{Login: "acme"}},
	}
	gh.addWorkflow(".github/workflows/ci.yml", "sha1", loadVulnerableWorkflow(t))

	scanner_ := &OrgScanner{Client: newTestGitHubClient(t, gh.server.URL)}
	res, err := scanner_.Scan(context.Background(), "tok", "acme", OrgScanOptions{Ruleset: "all"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Repos) != 2 {
		t.Fatalf("expected 2 repos scanned, got %d", len(res.Repos))
	}

	findings, _ := res.Flatten()
	if len(findings) == 0 {
		t.Fatal("expected findings across the org")
	}
	// Every workflow finding's file must be prefixed with its repo full name.
	var sawWeb, sawAPI bool
	for _, f := range findings {
		if f.File == scanner.SettingsFile {
			continue
		}
		if !strings.HasPrefix(f.File, "acme/web/") && !strings.HasPrefix(f.File, "acme/api/") {
			t.Errorf("finding file %q not prefixed with a repo full name", f.File)
		}
		sawWeb = sawWeb || strings.HasPrefix(f.File, "acme/web/")
		sawAPI = sawAPI || strings.HasPrefix(f.File, "acme/api/")
	}
	if !sawWeb || !sawAPI {
		t.Errorf("expected findings from both repos (web=%v api=%v)", sawWeb, sawAPI)
	}

	// Deterministic order: api sorts before web.
	if res.Repos[0].FullName != "acme/api" || res.Repos[1].FullName != "acme/web" {
		t.Errorf("repos not sorted deterministically: %s, %s", res.Repos[0].FullName, res.Repos[1].FullName)
	}
}

func TestOrgScanUnknownOwner(t *testing.T) {
	gh := newMockGitHub(t)
	gh.ownerRepos = nil // both org and user endpoints 404
	s := &OrgScanner{Client: newTestGitHubClient(t, gh.server.URL)}
	if _, err := s.Scan(context.Background(), "tok", "ghost", OrgScanOptions{}); err == nil {
		t.Fatal("expected an error for an unknown owner")
	}
}

func TestOrgScanRulesetFilter(t *testing.T) {
	gh := newMockGitHub(t)
	gh.ownerRepos = []Repo{{Name: "web", FullName: "acme/web", DefaultBranch: "main", Owner: struct {
		Login string `json:"login"`
	}{Login: "acme"}}}
	gh.addWorkflow(".github/workflows/ci.yml", "sha1", loadVulnerableWorkflow(t))

	s := &OrgScanner{Client: newTestGitHubClient(t, gh.server.URL)}
	res, err := s.Scan(context.Background(), "tok", "acme", OrgScanOptions{Ruleset: "owasp"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	findings, _ := res.Flatten()
	// owasp filter: no BEST-PRAC-only rule should survive.
	for _, f := range findings {
		if f.RuleID == scanner.RuleSelfHostedRunners {
			t.Errorf("owasp ruleset leaked a non-OWASP rule: %s", f.RuleID)
		}
	}
}
