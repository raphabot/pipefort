package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/raphabot/pipefort/pkg/scanner"
)

func TestOnlineAuditsEnabled(t *testing.T) {
	cases := []struct {
		name      string
		auditPins bool
		offline   bool
		token     string
		want      bool
	}{
		{"default no token", false, false, "", false},
		{"token auto-enables", false, false, "ghp_x", true},
		{"explicit flag without token", true, false, "", true},
		{"explicit flag with token", true, false, "ghp_x", true},
		{"offline beats token", false, true, "ghp_x", false},
		{"offline beats explicit flag", true, true, "ghp_x", false},
		{"offline beats flag without token", true, true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := onlineAuditsEnabled(tc.auditPins, tc.offline, tc.token); got != tc.want {
				t.Errorf("onlineAuditsEnabled(%v, %v, %q) = %v, want %v", tc.auditPins, tc.offline, tc.token, got, tc.want)
			}
		})
	}
}

func TestOnlineAuditHint(t *testing.T) {
	cases := []struct {
		name        string
		offline     bool
		auditPins   bool
		explicit    string
		resolved    string
		hasRefs     bool
		wantMessage bool
	}{
		{"gh login, pinned actions, no explicit token", false, false, "", "gh-token", true, true},
		{"no gh login", false, false, "", "", true, false},
		{"no pinned actions", false, false, "", "gh-token", false, false},
		{"explicit token (audits already on)", false, false, "env-token", "env-token", true, false},
		{"offline suppresses", true, false, "", "gh-token", true, false},
		{"audit-pins forces on (no hint)", false, true, "", "gh-token", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := onlineAuditHint(tc.offline, tc.auditPins, tc.explicit, tc.resolved, tc.hasRefs)
			if (got != "") != tc.wantMessage {
				t.Errorf("onlineAuditHint(...) = %q, want message=%v", got, tc.wantMessage)
			}
		})
	}
}

func TestExplicitGitHubToken(t *testing.T) {
	origFlag := githubToken
	defer func() { githubToken = origFlag }()

	t.Run("flag wins over env", func(t *testing.T) {
		githubToken = "flag-token"
		t.Setenv("GITHUB_TOKEN", "env-token")
		if got := explicitGitHubToken(); got != "flag-token" {
			t.Errorf("got %q, want flag-token", got)
		}
	})

	t.Run("GITHUB_TOKEN wins over GH_TOKEN", func(t *testing.T) {
		githubToken = ""
		t.Setenv("GITHUB_TOKEN", "env-token")
		t.Setenv("GH_TOKEN", "gh-env-token")
		if got := explicitGitHubToken(); got != "env-token" {
			t.Errorf("got %q, want env-token", got)
		}
	})

	t.Run("GH_TOKEN as fallback", func(t *testing.T) {
		githubToken = ""
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "gh-env-token")
		if got := explicitGitHubToken(); got != "gh-env-token" {
			t.Errorf("got %q, want gh-env-token", got)
		}
	})

	t.Run("no explicit sources", func(t *testing.T) {
		githubToken = ""
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "")
		if got := explicitGitHubToken(); got != "" {
			t.Errorf("got %q, want empty (gh auth token fallback must not count as explicit)", got)
		}
	})
}

func TestLoadRepoConfig(t *testing.T) {
	// Reset package-level flag state between subtests.
	reset := func() { configPath, noConfig, scanFile, gitRepo = "", false, "", "" }

	t.Run("discovers .pipefort.yml in scan root", func(t *testing.T) {
		reset()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".pipefort.yml"), []byte("persona: auditor\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadRepoConfig(dir)
		if err != nil {
			t.Fatalf("loadRepoConfig: %v", err)
		}
		if cfg == nil || cfg.Persona != "auditor" {
			t.Fatalf("expected persona=auditor, got %+v", cfg)
		}
	})

	t.Run("--no-config ignores a present file", func(t *testing.T) {
		reset()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".pipefort.yml"), []byte("persona: auditor\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		noConfig = true
		cfg, err := loadRepoConfig(dir)
		if err != nil || cfg != nil {
			t.Fatalf("expected nil config with --no-config, got %+v (%v)", cfg, err)
		}
	})

	t.Run("--config points at an explicit file", func(t *testing.T) {
		reset()
		dir := t.TempDir()
		p := filepath.Join(dir, "custom.yml")
		if err := os.WriteFile(p, []byte("ruleset: owasp\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		configPath = p
		cfg, err := loadRepoConfig(dir)
		if err != nil {
			t.Fatalf("loadRepoConfig: %v", err)
		}
		if cfg == nil || cfg.Ruleset != "owasp" {
			t.Fatalf("expected ruleset=owasp, got %+v", cfg)
		}
	})

	t.Run("no config present returns nil", func(t *testing.T) {
		reset()
		cfg, err := loadRepoConfig(t.TempDir())
		if err != nil || cfg != nil {
			t.Fatalf("expected (nil,nil), got %+v (%v)", cfg, err)
		}
	})

	var _ = scanner.RepoConfig{} // keep the scanner import referenced
}
