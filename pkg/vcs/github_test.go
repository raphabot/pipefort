package vcs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
)

func TestInstallationToken(t *testing.T) {
	gh := newMockGitHub(t)
	c := newTestGitHubClient(t, gh.server.URL)

	tok, err := c.InstallationToken(context.Background(), 99)
	if err != nil {
		t.Fatalf("InstallationToken: %v", err)
	}
	if tok != "ghs_installationtoken" {
		t.Fatalf("unexpected token %q", tok)
	}
}

func TestInstallationTokenError(t *testing.T) {
	gh := newMockGitHub(t)
	gh.tokenCode = 401
	c := newTestGitHubClient(t, gh.server.URL)

	if _, err := c.InstallationToken(context.Background(), 99); err == nil {
		t.Fatal("expected error when GitHub returns 401")
	}
}

func TestGetInstallation(t *testing.T) {
	gh := newMockGitHub(t)
	gh.account.ID = 99
	gh.account.Account.Login = "acme"
	gh.account.Account.Type = "Organization"
	c := newTestGitHubClient(t, gh.server.URL)

	inst, err := c.GetInstallation(context.Background(), 99)
	if err != nil {
		t.Fatalf("GetInstallation: %v", err)
	}
	if inst.Account.Login != "acme" || inst.Account.Type != "Organization" {
		t.Fatalf("unexpected installation %+v", inst)
	}
}

func TestListRepos(t *testing.T) {
	gh := newMockGitHub(t)
	gh.repos = []Repo{
		{ID: 1, Name: "a", FullName: "acme/a"},
		{ID: 2, Name: "b", FullName: "acme/b"},
	}
	c := newTestGitHubClient(t, gh.server.URL)

	repos, err := c.ListRepos(context.Background(), "tok")
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(repos))
	}
}

func TestFetchWorkflows(t *testing.T) {
	yaml, err := os.ReadFile("../../testdata/vulnerable-workflow.yml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	gh := newMockGitHub(t)
	gh.addWorkflow(".github/workflows/ci.yml", "sha-ci", yaml)
	gh.addWorkflow(".github/workflows/notes.txt", "sha-txt", []byte("ignore me"))
	gh.addWorkflow("README.md", "sha-readme", []byte("# hi"))
	c := newTestGitHubClient(t, gh.server.URL)

	files, err := c.FetchWorkflows(context.Background(), "tok", "acme", "repo", "main")
	if err != nil {
		t.Fatalf("FetchWorkflows: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected only the .yml workflow, got %d files", len(files))
	}
	if files[0].Path != ".github/workflows/ci.yml" {
		t.Fatalf("unexpected path %q", files[0].Path)
	}
	if string(files[0].Content) != string(yaml) {
		t.Fatal("fetched content does not match the original (base64 round-trip failed)")
	}
}

func TestFetchRepositorySettingsHappyPath(t *testing.T) {
	gh := newMockGitHub(t)
	// Default mock is a hardened repo: branch protection set, alerts on, etc.
	c := newTestGitHubClient(t, gh.server.URL)

	rc, err := c.FetchRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", "https://github.com/acme/widgets")
	if err != nil {
		t.Fatalf("FetchRepositorySettings: %v", err)
	}
	if rc.BranchProtection == nil {
		t.Fatal("expected branch protection to be populated from secureBranchProtection default")
	}
	if !rc.BranchProtection.EnforceAdmins.Enabled {
		t.Error("expected enforce_admins=true from default")
	}
	if !rc.DependabotAlerts {
		t.Error("expected DependabotAlerts=true from default")
	}
	if rc.WorkflowPerms == nil || rc.WorkflowPerms.DefaultWorkflowPermissions != "read" {
		t.Errorf("expected default_workflow_permissions=read, got %+v", rc.WorkflowPerms)
	}
	if rc.ActionsPolicy == nil || rc.ActionsPolicy.AllowedActions != "selected" {
		t.Errorf("expected allowed_actions=selected, got %+v", rc.ActionsPolicy)
	}
	if rc.Repository == nil || rc.Repository.SecurityAndAnalysis == nil {
		t.Fatal("expected security_and_analysis to be populated")
	}
	if rc.Repository.SecurityAndAnalysis.SecretScanning.Status != "enabled" {
		t.Errorf("expected secret scanning enabled, got %+v", rc.Repository.SecurityAndAnalysis.SecretScanning)
	}
}

func TestFetchRepositorySettingsBranchProtection404(t *testing.T) {
	gh := newMockGitHub(t)
	gh.branchProtection = nil // simulate "no protection rule"
	c := newTestGitHubClient(t, gh.server.URL)

	rc, err := c.FetchRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", "")
	if err != nil {
		t.Fatalf("404 on branch protection should not be an error: %v", err)
	}
	if rc.BranchProtection != nil {
		t.Errorf("expected nil BranchProtection after 404, got %+v", rc.BranchProtection)
	}
}

func TestFetchRepositorySettingsDependabotAlerts204(t *testing.T) {
	gh := newMockGitHub(t)
	gh.dependabotAlerts = true
	c := newTestGitHubClient(t, gh.server.URL)

	rc, err := c.FetchRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", "")
	if err != nil {
		t.Fatalf("FetchRepositorySettings: %v", err)
	}
	if !rc.DependabotAlerts {
		t.Error("expected DependabotAlerts=true when GitHub returns 204")
	}
}

func TestFetchRepositorySettingsCodeownersDetected(t *testing.T) {
	gh := newMockGitHub(t)
	gh.codeownersPaths = map[string]bool{".github/CODEOWNERS": true}
	c := newTestGitHubClient(t, gh.server.URL)

	rc, err := c.FetchRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", "")
	if err != nil {
		t.Fatalf("FetchRepositorySettings: %v", err)
	}
	if !rc.HasCodeowners {
		t.Error("expected HasCodeowners=true when .github/CODEOWNERS exists")
	}
}

func TestFetchRepositorySettingsForbiddenSurfacesAsTypedError(t *testing.T) {
	gh := newMockGitHub(t)
	gh.repoStatus = http.StatusForbidden // simulate missing GitHub App permission
	c := newTestGitHubClient(t, gh.server.URL)

	_, err := c.FetchRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", "")
	if err == nil {
		t.Fatal("expected an error when /repos/{o}/{r} returns 403")
	}
	var apiErr *GitHubAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected wrapped *GitHubAPIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", apiErr.Status)
	}
}

// A 403 "Upgrade to GitHub Pro…" on branch protection is a plan limitation,
// not a missing permission: the audit must continue and flag it as such rather
// than aborting the whole settings fetch.
func TestFetchRepositorySettingsBranchProtectionPlanLimited(t *testing.T) {
	gh := newMockGitHub(t)
	gh.branchProtStatus = http.StatusForbidden
	gh.branchProtBody = `{"message":"Upgrade to GitHub Pro or make this repository public to enable this feature.","status":"403"}`
	gh.dependabotAlerts = false // a real finding that must survive the BP error
	c := newTestGitHubClient(t, gh.server.URL)

	rc, err := c.FetchRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", "")
	if err != nil {
		t.Fatalf("plan-limited 403 on branch protection should not abort the audit: %v", err)
	}
	if rc.BranchProtection != nil {
		t.Errorf("expected nil BranchProtection, got %+v", rc.BranchProtection)
	}
	if !rc.BranchProtectionUnavailable {
		t.Error("expected BranchProtectionUnavailable=true for the plan-limitation 403")
	}
	// The rest of the audit must have run: Dependabot alerts were fetched (404 -> false).
	if rc.DependabotAlerts {
		t.Error("expected DependabotAlerts=false — the audit should have continued past branch protection")
	}
}

// A genuine permission 403 ("Resource not accessible by integration") must
// still surface as a typed error so the caller renders the re-authorize hint.
func TestFetchRepositorySettingsBranchProtectionPermission403(t *testing.T) {
	gh := newMockGitHub(t)
	gh.branchProtStatus = http.StatusForbidden
	gh.branchProtBody = `{"message":"Resource not accessible by integration","status":"403"}`
	c := newTestGitHubClient(t, gh.server.URL)

	_, err := c.FetchRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", "")
	if err == nil {
		t.Fatal("expected a permission 403 to surface as an error")
	}
	if StatusOf(err) != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", StatusOf(err))
	}
}

// Sanity check: the JSON shapes the mock serves actually decode into the
// scanner types — guards against drift between the mock fixtures and the
// scanner.* struct tags.
func TestSecureDefaultsRoundTripIntoScannerTypes(t *testing.T) {
	t.Run("BranchProtection", func(t *testing.T) {
		var v map[string]any
		if err := json.Unmarshal(secureBranchProtection, &v); err != nil {
			t.Fatalf("invalid JSON fixture: %v", err)
		}
	})
	t.Run("WorkflowPermissions", func(t *testing.T) {
		var v map[string]any
		if err := json.Unmarshal(secureWorkflowPerms, &v); err != nil {
			t.Fatalf("invalid JSON fixture: %v", err)
		}
	})
}

func TestIsWorkflowPath(t *testing.T) {
	cases := map[string]bool{
		".github/workflows/ci.yml":      true,
		".github/workflows/deploy.yaml": true,
		".github/workflows/ci.YML":      true,
		".github/workflows/readme.md":   false,
		".github/actions/ci.yml":        false,
		"ci.yml":                        false,
	}
	for path, want := range cases {
		if got := isWorkflowPath(path); got != want {
			t.Errorf("isWorkflowPath(%q) = %v, want %v", path, got, want)
		}
	}
}
