package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	pipefortmcp "github.com/raphabot/pipefort/pkg/mcp"
	"github.com/raphabot/pipefort/pkg/reporter"
	"github.com/raphabot/pipefort/pkg/scanner"
	"github.com/raphabot/pipefort/pkg/vcs"
)

var (
	scanPath       string
	scanFile       string
	gitRepo        string
	orgTarget      string
	outputFormat   string
	failOnSeverity string
	ruleset        string
	minConfidence  string
	persona        string
	keepTemp       bool
	fixFindings    bool
	fixSettings    bool
	fixSettingsGL  bool
	fixMR          bool
	dryRun         bool
	auditPins      bool
	offline        bool
	githubToken    string
	gitlabToken    string
	gitlabHost     string
	configPath     string
	noConfig       bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "pipefort",
		Short: "pipefort inspects CI/CD pipelines for security vulnerabilities",
		Long: `A CLI tool that inspects local directories or remote repositories
(GitHub Actions or GitLab CI) for security risks in their pipelines matching
the OWASP Top 10 CI/CD Security Risks.`,
		RunE: runScan,
	}

	rootCmd.Flags().StringVarP(&scanPath, "path", "p", ".", "Path to the local repository or directory to scan")
	rootCmd.Flags().StringVarP(&scanFile, "file", "f", "", "Scan a single specific workflow file")
	rootCmd.Flags().StringVarP(&gitRepo, "git", "g", "", "Remote repository to scan. Accepts 'owner/repo' (GitHub), a full GitHub URL, or a full GitLab URL (gitlab.com or self-hosted).")
	rootCmd.Flags().StringVar(&orgTarget, "org", "", "Scan every repository owned by a GitHub organization or user, fetching workflows over the API (no cloning). Requires a token (--github-token / $GITHUB_TOKEN / $GH_TOKEN / `gh auth token`). --fail-on applies to the aggregate.")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "console", "Output format: 'console', 'json', or 'sarif' (SARIF 2.1.0 for GitHub code scanning)")
	rootCmd.Flags().StringVarP(&failOnSeverity, "fail-on", "s", "MEDIUM", "Fail (exit code 1) on findings at or above this severity: 'HIGH', 'MEDIUM', 'LOW', 'INFO', or 'NONE'")
	rootCmd.Flags().StringVarP(&ruleset, "ruleset", "r", "all", "Ruleset to execute: 'all', 'owasp', 'slsa' (any SLSA v1.2 level), 'slsa-build-l1|l2|l3', or 'slsa-source-l2|l3|l4'")
	rootCmd.Flags().StringVar(&minConfidence, "min-confidence", "LOW", "Drop findings below this confidence: 'HIGH', 'MEDIUM', or 'LOW' (default keeps everything)")
	rootCmd.Flags().StringVar(&persona, "persona", "regular", "Noise tier: 'regular' (high-signal security checks), 'pedantic' (adds hygiene nits like missing timeouts), or 'auditor' (everything)")
	rootCmd.Flags().BoolVar(&keepTemp, "keep-temp", false, "Keep cloned temporary repository directories (do not delete them after scan)")
	rootCmd.Flags().BoolVar(&fixFindings, "fix", false, "Attempt to automatically fix detected vulnerabilities/risks in workflow files in-place (works for both GitHub Actions and GitLab CI YAML).")
	rootCmd.Flags().BoolVar(&fixSettings, "fix-settings", false, "Apply auto-fixable repository-configuration findings against the GitHub API (requires --git pointing at GitHub and a token with administration:write). Print actions; pair with --dry-run to preview without writing.")
	rootCmd.Flags().BoolVar(&fixSettingsGL, "fix-settings-gl", false, "Apply auto-fixable GitLab project-settings findings via the GitLab API (requires --git pointing at GitLab and --gitlab-token). Fixes 'pipelines must succeed' and public-pipelines; pair with --dry-run to preview.")
	rootCmd.Flags().BoolVar(&fixMR, "fix-mr", false, "Open Merge Requests on GitLab for each auto-fixable workflow finding. Requires --git pointing at GitLab and --gitlab-token with `api` scope. Pair with --dry-run to preview.")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview mutations without writing. Applies to --fix-settings and --fix-mr.")
	rootCmd.Flags().BoolVar(&auditPins, "audit-pins", false, "Force online supply-chain audits of pinned actions (known-vulnerable, impostor-commit, ref/version-mismatch, typosquat) even without a token, accepting GitHub's 60-requests/hour anonymous limit. These audits already run automatically when a GitHub token is available; use --offline to disable them.")
	rootCmd.Flags().BoolVar(&offline, "offline", false, "Disable every network-backed audit: online pin audits and repository-settings checks. Only `git clone` traffic remains for --git targets.")
	rootCmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub token (PAT or `gh auth token` output) used by --git to also audit repository settings. Falls back to $GITHUB_TOKEN.")
	rootCmd.Flags().StringVar(&gitlabToken, "gitlab-token", "", "GitLab token (PAT with `api` scope or `glab auth token` output) used by --git for GitLab targets. Falls back to $GITLAB_TOKEN.")
	rootCmd.Flags().StringVar(&gitlabHost, "gitlab-host", "gitlab.com", "GitLab host for project-settings audits when scanning a local --path/--file. Ignored when --git carries an https URL (the host is parsed from the URL).")
	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to a .pipefort.yml config file. Defaults to discovering .pipefort.yml (or .github/pipefort.yml) in the scan root. Provides rule enable/disable, severity overrides, per-file/line ignores, and default ruleset/persona/min-confidence.")
	rootCmd.Flags().BoolVar(&noConfig, "no-config", false, "Ignore any .pipefort.yml config file for this run.")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "mcp",
		Short: "Run Pipefort as a Model Context Protocol server over stdio",
		Long: `Serve Pipefort's scanner over the Model Context Protocol (stdio), so AI
coding assistants can scan CI workflows as they write them. Register it with your
assistant as a command-based MCP server running "pipefort mcp".`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return pipefortmcp.Run(cmd.Context())
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Org-wide scan is a distinct path: enumerate an owner's repos and scan
	// each over the API, no cloning. Handled up front and returns early.
	if orgTarget != "" {
		return runOrgScan(cmd)
	}

	var targetPath string
	var tempDir string
	var err error

	// 1. Resolve the remote target (if any) and clone.
	var target gitTarget
	if gitRepo != "" {
		target, err = detectTarget(gitRepo)
		if err != nil {
			return fmt.Errorf("parse --git: %w", err)
		}
		fmt.Printf("Cloning remote %s repository: %s/%s...\n", target.Provider, target.Owner, target.Name)
		tempDir, err = cloneRemoteRepo(target)
		if err != nil {
			return fmt.Errorf("failed to clone repository %s: %w", gitRepo, err)
		}
		targetPath = tempDir

		if !keepTemp {
			defer func() {
				fmt.Printf("Cleaning up temporary directory %s...\n", tempDir)
				os.RemoveAll(tempDir)
			}()
		} else {
			fmt.Printf("Temporary clone kept at: %s\n", tempDir)
		}
	} else if scanFile != "" {
		targetPath = scanFile
	} else {
		targetPath = scanPath
	}

	// 1b. Load the in-repo config (.pipefort.yml). --no-config skips it;
	// --config points at an explicit file. Otherwise it is discovered in the
	// scan root (the clone dir, the file's directory, or the scanned path).
	cfg, err := loadRepoConfig(targetPath)
	if err != nil {
		return err
	}

	// 2. Perform the scan
	var findings []scanner.Finding
	if scanFile != "" {
		findings, err = scanner.ScanFile(targetPath)
	} else {
		findings, err = scanner.ScanDir(targetPath)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// 2b. Repository-settings audit. GitHub only in v1 — GitLab's project
	// settings surface is reserved for a follow-up release.
	if gitRepo != "" && target.Provider == "github" && !offline {
		token := resolveGitHubToken()
		if token == "" {
			fmt.Fprintln(os.Stderr, "Info: skipping repository-settings checks for --git scans — pass --github-token (or set $GITHUB_TOKEN) to enable them.")
		} else {
			settingsFindings, err := scanRepositorySettings(target.Owner+"/"+target.Name, token)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: repository-settings audit failed for %s/%s: %v\n", target.Owner, target.Name, err)
			} else {
				findings = append(findings, settingsFindings...)
			}

			if fixSettings {
				findings = applyRepositorySettingsFix(target.Owner+"/"+target.Name, token, findings)
			}
		}
	} else if fixSettings {
		if offline {
			fmt.Fprintln(os.Stderr, "Warning: --fix-settings needs network access and is disabled by --offline.")
		} else {
			fmt.Fprintln(os.Stderr, "Warning: --fix-settings only applies to GitHub --git targets in v1.")
		}
	}

	// 2c. GitLab project-settings audit (merge policy, protected branch,
	// public pipelines, approvals). GitLab --git targets only.
	if gitRepo != "" && target.Provider == "gitlab" && !offline {
		token := resolveGitLabToken()
		if token == "" {
			fmt.Fprintln(os.Stderr, "Info: skipping GitLab project-settings checks — pass --gitlab-token (or set $GITLAB_TOKEN) to enable them.")
		} else {
			glFindings, glErr := scanGitLabProjectSettings(target, token)
			if glErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: GitLab project-settings audit failed for %s/%s: %v\n", target.Owner, target.Name, glErr)
			} else {
				findings = append(findings, glFindings...)
			}
			if fixSettingsGL {
				findings = applyGitLabSettingsFix(target, token, findings)
			}
		}
	} else if fixSettingsGL {
		if offline {
			fmt.Fprintln(os.Stderr, "Warning: --fix-settings-gl needs network access and is disabled by --offline.")
		} else {
			fmt.Fprintln(os.Stderr, "Warning: --fix-settings-gl only applies to GitLab --git targets.")
		}
	}

	if fixFindings {
		if gitRepo != "" {
			fmt.Fprintln(os.Stderr, "Warning: --fix only applies to local scans (--path/--file). Use --fix-mr to open a GitLab MR or the web app to open a GitHub PR.")
		} else {
			fixedCount, fixErr := scanner.FixFindings(targetPath, findings)
			if fixErr != nil {
				return fmt.Errorf("failed to apply fixes: %w", fixErr)
			}
			if fixedCount > 0 {
				fmt.Printf("Successfully fixed %d vulnerabilities in-place.\n", fixedCount)
				if scanFile != "" {
					findings, err = scanner.ScanFile(targetPath)
				} else {
					findings, err = scanner.ScanDir(targetPath)
				}
				if err != nil {
					return fmt.Errorf("scan failed after applying fixes: %w", err)
				}
			} else {
				fmt.Println("No auto-fixable vulnerabilities found.")
			}
		}
	}

	// 2d. --fix-mr — open a GitLab Merge Request per fixable workflow
	// finding. Requires a GitLab target plus --gitlab-token with api scope.
	if fixMR {
		if gitRepo == "" || target.Provider != "gitlab" {
			fmt.Fprintln(os.Stderr, "Warning: --fix-mr requires --git pointing at a GitLab repository.")
		} else {
			token := resolveGitLabToken()
			if token == "" {
				fmt.Fprintln(os.Stderr, "Warning: --fix-mr needs --gitlab-token (or $GITLAB_TOKEN).")
			} else {
				applyGitLabMRFix(target, token, findings)
			}
		}
	}

	// 2e. Online supply-chain audits of pinned actions. Auto-enabled whenever a
	// GitHub token is available (matching the settings audit); --audit-pins
	// forces them on without one, --offline forces them off. Runs after the
	// offline scan so its findings flow through ruleset filtering,
	// toxic-combination correlation, and reporting like any other.
	if onlineAuditsEnabled(auditPins, offline, explicitGitHubToken()) {
		pinToken := resolveGitHubToken()
		var refs []scanner.ActionRef
		if scanFile != "" {
			if content, readErr := os.ReadFile(targetPath); readErr == nil {
				refs = scanner.CollectActionRefsFromBytes(targetPath, content)
			}
		} else {
			refs = scanner.CollectActionRefsFromDir(targetPath)
		}
		if len(refs) > 0 {
			if pinToken == "" {
				fmt.Fprintln(os.Stderr, "Info: --audit-pins running unauthenticated — pass --github-token (or set $GITHUB_TOKEN) to avoid GitHub's 60-requests/hour anonymous limit.")
			} else if !auditPins {
				fmt.Fprintln(os.Stderr, "Info: online supply-chain pin audits enabled (GitHub token detected) — pass --offline to disable.")
			}
			auditor := scanner.NewGitHubPinAuditor(pinToken)
			pinFindings := scanner.AuditActionPins(context.Background(), refs, auditor)
			findings = append(findings, pinFindings...)
		}
	} else if !offline && !auditPins && explicitGitHubToken() == "" {
		// Online audits are off. A `gh auth token` login does NOT silently
		// enable them (a local scan shouldn't start calling api.github.com just
		// because gh is authenticated). But when the scan has pinned actions to
		// audit and a gh login is available, nudge the user that the audits
		// exist — without making the network calls. The ref walk gates the
		// (subprocess) gh lookup so it only runs when there's something to audit.
		var refs []scanner.ActionRef
		if scanFile != "" {
			if content, readErr := os.ReadFile(targetPath); readErr == nil {
				refs = scanner.CollectActionRefsFromBytes(targetPath, content)
			}
		} else {
			refs = scanner.CollectActionRefsFromDir(targetPath)
		}
		if len(refs) > 0 {
			if msg := onlineAuditHint(offline, auditPins, explicitGitHubToken(), resolveGitHubToken(), true); msg != "" {
				fmt.Fprintln(os.Stderr, msg)
			}
		}
	}

	// Forbidden-uses policy (offline, config-driven). Enforces the .pipefort.yml
	// allow/deny list of action references; silent when no policy is configured.
	if cfg != nil && cfg.ForbiddenUses != nil {
		var refs []scanner.ActionRef
		if scanFile != "" {
			if content, readErr := os.ReadFile(targetPath); readErr == nil {
				refs = scanner.CollectActionRefsFromBytes(targetPath, content)
			}
		} else {
			refs = scanner.CollectActionRefsFromDir(targetPath)
		}
		findings = append(findings, scanner.CheckForbiddenUses(refs, cfg.ForbiddenUses)...)
	}

	// Normalize temp-clone paths to repo-relative first, so the config's
	// per-file ignore globs (which are repo-relative) match.
	if tempDir != "" {
		for i := range findings {
			if relPath, relErr := filepath.Rel(tempDir, findings[i].File); relErr == nil {
				findings[i].File = relPath
			}
		}
	}

	// Apply the in-repo config: disabled rules, per-file/line ignores, and
	// severity overrides. Runs before ruleset/persona/confidence filtering so a
	// config-disabled rule can't form a toxic combination.
	findings = scanner.ApplyRepoConfig(findings, cfg)

	// Resolve the effective ruleset / persona / min-confidence. An explicit CLI
	// flag always wins; otherwise the config value (if any) applies; otherwise
	// the flag default. This is the CLI > config > default precedence.
	effRuleset := resolveStringSetting(cmd, "ruleset", ruleset, configString(cfg, "ruleset"))
	effPersona := resolveStringSetting(cmd, "persona", persona, configString(cfg, "persona"))
	effMinConf := resolveStringSetting(cmd, "min-confidence", minConfidence, configString(cfg, "min-confidence"))

	findings = scanner.FilterFindings(findings, effRuleset)
	findings = scanner.FilterByPersona(findings, scanner.Persona(strings.ToLower(strings.TrimSpace(effPersona))))
	findings = scanner.FilterByConfidence(findings, scanner.Confidence(strings.ToUpper(strings.TrimSpace(effMinConf))))

	// Correlate findings into toxic combinations ("Attacker Mind"). Runs on the
	// already-filtered, path-rewritten findings so disabled rules can't form a
	// combo and component paths match the report.
	combos := scanner.DetectToxicCombinations(findings)

	// 3. Output results
	switch strings.ToLower(outputFormat) {
	case "json":
		if err := reporter.ReportJSONWithCombos(os.Stdout, findings, combos); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}
	case "sarif":
		// SARIF carries the flat findings list only — it feeds GitHub code
		// scanning (github/codeql-action/upload-sarif). Toxic combinations have
		// no SARIF analog and are omitted.
		if err := reporter.ReportSARIF(os.Stdout, findings); err != nil {
			return fmt.Errorf("failed to write SARIF output: %w", err)
		}
	default:
		reporter.ReportConsole(os.Stdout, findings)
		reporter.ReportCombos(os.Stdout, combos)
	}

	// 4. Check if we should return failure exit code
	if shouldFail(findings, failOnSeverity) {
		os.Exit(1)
	}

	return nil
}

// runOrgScan scans every repository owned by --org over the GitHub API and
// reports the aggregate. Requires a token; --fail-on applies to the whole org.
func runOrgScan(cmd *cobra.Command) error {
	token := resolveGitHubToken()
	if token == "" {
		return fmt.Errorf("--org needs a GitHub token: pass --github-token, or set $GITHUB_TOKEN / $GH_TOKEN, or run `gh auth login`")
	}
	if fixFindings || fixSettings || fixMR {
		fmt.Fprintln(os.Stderr, "Warning: --fix flags are ignored with --org (org scans are read-only).")
	}

	opts := vcs.OrgScanOptions{
		Ruleset:       ruleset,
		Persona:       scanner.Persona(strings.ToLower(strings.TrimSpace(persona))),
		MinConfidence: scanner.Confidence(strings.ToUpper(strings.TrimSpace(minConfidence))),
		Online:        onlineAuditsEnabled(auditPins, offline, explicitGitHubToken()),
	}

	fmt.Fprintf(os.Stderr, "Scanning all repositories for %s...\n", orgTarget)
	result, err := vcs.NewOrgScanner().Scan(context.Background(), token, orgTarget, opts)
	if err != nil {
		return fmt.Errorf("org scan: %w", err)
	}

	findings, combos := result.Flatten()

	switch strings.ToLower(outputFormat) {
	case "json":
		if err := reporter.ReportJSONWithCombos(os.Stdout, findings, combos); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}
	case "sarif":
		if err := reporter.ReportSARIF(os.Stdout, findings); err != nil {
			return fmt.Errorf("failed to write SARIF output: %w", err)
		}
	default:
		// Per-repo summary table first, then the full flat report.
		fmt.Fprintf(os.Stdout, "\n--- ORG SCAN: %s (%d repositories) ---\n", orgTarget, len(result.Repos))
		lines := result.SeverityLines()
		if len(lines) == 0 {
			fmt.Fprintln(os.Stdout, "No findings across any repository.")
		} else {
			for _, l := range lines {
				fmt.Fprintf(os.Stdout, "  %s\n", l)
			}
		}
		for _, e := range result.Errors() {
			fmt.Fprintf(os.Stderr, "  ! %s\n", e)
		}
		reporter.ReportConsole(os.Stdout, findings)
		reporter.ReportCombos(os.Stdout, combos)
	}

	if shouldFail(findings, failOnSeverity) {
		os.Exit(1)
	}
	return nil
}

// loadRepoConfig resolves the .pipefort.yml for a scan. --no-config disables
// it, --config points at an explicit file, and otherwise it is discovered in
// the scan root. targetPath is the clone dir, the single file, or the scanned
// path; the config directory is derived from it. Prints an info line when a
// config is applied.
func loadRepoConfig(targetPath string) (*scanner.RepoConfig, error) {
	if noConfig {
		return nil, nil
	}
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read --config %s: %w", configPath, err)
		}
		cfg, err := scanner.ParseRepoConfig(data)
		if err != nil {
			return nil, fmt.Errorf("parse --config %s: %w", configPath, err)
		}
		fmt.Fprintf(os.Stderr, "Info: applying config %s\n", configPath)
		return cfg, nil
	}

	// Discover in the scan root. For --file the root is the file's directory.
	dir := targetPath
	if scanFile != "" && gitRepo == "" {
		dir = filepath.Dir(targetPath)
	}
	cfg, name, err := scanner.LoadRepoConfig(dir)
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		fmt.Fprintf(os.Stderr, "Info: applying config %s\n", name)
	}
	return cfg, nil
}

// resolveStringSetting implements CLI > config > default precedence: an
// explicitly-set flag wins; otherwise a non-empty config value applies;
// otherwise the flag's default (its current value) stands.
func resolveStringSetting(cmd *cobra.Command, flag, flagVal, cfgVal string) string {
	if cmd.Flags().Changed(flag) {
		return flagVal
	}
	if cfgVal != "" {
		return cfgVal
	}
	return flagVal
}

// configString pulls a top-level string setting from the config, or "".
func configString(cfg *scanner.RepoConfig, key string) string {
	if cfg == nil {
		return ""
	}
	switch key {
	case "ruleset":
		return cfg.Ruleset
	case "persona":
		return cfg.Persona
	case "min-confidence":
		return cfg.MinConfidence
	}
	return ""
}

// onlineAuditsEnabled decides whether the online supply-chain pin audits run.
// --offline always wins; an explicit --audit-pins forces them on even without
// a token (accepting GitHub's anonymous rate limit); otherwise they run
// exactly when the user deliberately supplied a token via --github-token,
// $GITHUB_TOKEN, or $GH_TOKEN. A token surfaced only by the `gh auth token`
// fallback does NOT auto-enable them — a plain local scan must not start
// making API calls just because gh happens to be logged in.
func onlineAuditsEnabled(explicitAuditPins, offline bool, explicitToken string) bool {
	if offline {
		return false
	}
	if explicitAuditPins {
		return true
	}
	return explicitToken != ""
}

// onlineAuditHint returns a one-line nudge (or "") telling the user that the
// online supply-chain audits are available. It fires only when the audits are
// off for a benign reason — not --offline, not --audit-pins, no explicit token
// — yet the scan has pinned actions (hasRefs) and a token is resolvable, which
// in this branch means a `gh auth token` login. The gh login never silently
// enables the audits; this only surfaces that it could.
func onlineAuditHint(offline, auditPins bool, explicitToken, resolvedToken string, hasRefs bool) string {
	if offline || auditPins || explicitToken != "" || !hasRefs || resolvedToken == "" {
		return ""
	}
	return "Info: GitHub CLI login detected — run with --audit-pins (or set $GITHUB_TOKEN / $GH_TOKEN) to enable online supply-chain audits of pinned actions (impostor-commit, known-vulnerable, archived, typosquat, …)."
}

// explicitGitHubToken returns a token the user deliberately supplied:
// --github-token, then $GITHUB_TOKEN, then $GH_TOKEN.
func explicitGitHubToken() string {
	if githubToken != "" {
		return githubToken
	}
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t
	}
	if t := strings.TrimSpace(os.Getenv("GH_TOKEN")); t != "" {
		return t
	}
	return ""
}

// resolveGitHubToken picks the first available token: the explicit sources,
// then `gh auth token` (silently ignored if gh isn't installed or isn't
// authenticated).
func resolveGitHubToken() string {
	if t := explicitGitHubToken(); t != "" {
		return t
	}
	if out, err := exec.Command("gh", "auth", "token").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

// resolveGitLabToken mirrors resolveGitHubToken: explicit --gitlab-token,
// then $GITLAB_TOKEN, then `glab auth token`.
func resolveGitLabToken() string {
	if gitlabToken != "" {
		return gitlabToken
	}
	if t := strings.TrimSpace(os.Getenv("GITLAB_TOKEN")); t != "" {
		return t
	}
	if out, err := exec.Command("glab", "auth", "token").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

// gitTarget identifies one remote repository across providers. Owner is the
// full namespace path on GitLab (e.g. "group/subgroup") and the owner slug
// on GitHub. Name is the repository / project name (no .git suffix).
type gitTarget struct {
	Provider string // "github" | "gitlab"
	Host     string // "github.com" / "gitlab.com" / "gitlab.acme.com"
	Owner    string
	Name     string
}

// detectTarget parses the --git input and routes it to the right provider.
// Accepted shapes (precedence in this order):
//
//   - https://gitlab.com/group/sub/project[.git]      → gitlab
//   - https://gitlab.acme.com/group/project[.git]     → gitlab (self-hosted)
//   - git@gitlab.com:group/project.git                → gitlab
//   - https://github.com/owner/repo[.git]             → github
//   - git@github.com:owner/repo.git                   → github
//   - owner/repo (no scheme, no host)                 → github (back-compat)
func detectTarget(input string) (gitTarget, error) {
	s := strings.TrimSpace(input)
	s = strings.TrimSuffix(s, ".git")

	// SSH form: git@host:path
	if strings.HasPrefix(s, "git@") {
		rest := strings.TrimPrefix(s, "git@")
		hostPart, path, ok := strings.Cut(rest, ":")
		if !ok {
			return gitTarget{}, fmt.Errorf("unrecognised SSH URL %q", input)
		}
		return targetFromHostPath(hostPart, path, input)
	}

	// HTTPS form: https://host/path
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
		s = strings.TrimPrefix(s, "https://")
		s = strings.TrimPrefix(s, "http://")
		hostPart, path, ok := strings.Cut(s, "/")
		if !ok {
			return gitTarget{}, fmt.Errorf("unrecognised URL %q", input)
		}
		return targetFromHostPath(hostPart, path, input)
	}

	// Bare owner/repo — historical GitHub shorthand.
	parts := strings.Split(s, "/")
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return gitTarget{Provider: "github", Host: "github.com", Owner: parts[0], Name: parts[1]}, nil
	}
	return gitTarget{}, fmt.Errorf("expected owner/repo or full URL, got %q", input)
}

func targetFromHostPath(host, path, input string) (gitTarget, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return gitTarget{}, fmt.Errorf("expected /owner/repo path in %q", input)
	}
	// Pick provider: github.com / *.github.com → github; everything else
	// defaults to gitlab. Users with a self-hosted GitHub Enterprise host
	// must use --github-token explicitly; for now we conservatively treat
	// unknown hosts as gitlab.
	provider := "gitlab"
	if host == "github.com" || strings.HasSuffix(host, ".github.com") {
		provider = "github"
	}
	owner := strings.Join(parts[:len(parts)-1], "/")
	name := parts[len(parts)-1]
	return gitTarget{Provider: provider, Host: host, Owner: owner, Name: name}, nil
}

// parseOwnerRepo keeps the older GitHub-only call sites working
// (applyRepositorySettingsFix, scanRepositorySettings).
func parseOwnerRepo(repo string) (owner, name string, err error) {
	t, err := detectTarget(repo)
	if err != nil {
		return "", "", err
	}
	if t.Provider != "github" {
		return "", "", fmt.Errorf("expected GitHub target, got %s host %s", t.Provider, t.Host)
	}
	return t.Owner, t.Name, nil
}

// applyRepositorySettingsFix invokes the GitHub-API auto-remediator against
// the repo-settings subset of findings. Prints each action (or would-be
// action) to stdout. Re-fetches settings findings afterward so the final
// report shows only what's left.
func applyRepositorySettingsFix(repo, token string, findings []scanner.Finding) []scanner.Finding {
	owner, name, err := parseOwnerRepo(repo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot parse --git target for --fix-settings: %v\n", err)
		return findings
	}

	// Pick out only the repo-settings findings the auto-fixer can act on.
	var settingsFindings []scanner.Finding
	for _, f := range findings {
		if f.File == scanner.SettingsFile {
			settingsFindings = append(settingsFindings, f)
		}
	}
	if len(settingsFindings) == 0 {
		return findings
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client := vcs.NewBareGitHubClient()
	htmlURL := fmt.Sprintf("https://github.com/%s/%s", owner, name)

	// Resolve default branch — needed for branch-protection fixes.
	rc, fetchErr := client.FetchRepositorySettings(ctx, token, owner, name, "", htmlURL)
	defaultBranch := "main"
	if fetchErr == nil && rc != nil && rc.DefaultBranch != "" {
		defaultBranch = rc.DefaultBranch
	}

	result := client.FixRepositorySettings(ctx, token, owner, name, defaultBranch, settingsFindings, dryRun)

	if dryRun {
		fmt.Println("\n--- REPOSITORY-SETTINGS FIX (DRY RUN) ---")
	} else {
		fmt.Println("\n--- REPOSITORY-SETTINGS FIX ---")
	}
	for _, action := range result.Applied {
		prefix := "✓"
		if dryRun {
			prefix = "→"
		}
		fmt.Printf("  %s %s\n", prefix, action.Description)
	}
	for _, e := range result.Errors {
		fmt.Fprintf(os.Stderr, "  ✗ %s: %s\n", e.RuleID, e.Message)
	}
	for _, skipped := range result.Skipped {
		fmt.Fprintf(os.Stderr, "  - %s: no auto-fix available\n", skipped)
	}

	if dryRun {
		// Don't re-scan in dry-run — nothing changed.
		return findings
	}

	// Re-scan repository settings to drop fixed findings from the final report.
	// Keep workflow-file findings (anything whose File != SettingsFile).
	var kept []scanner.Finding
	for _, f := range findings {
		if f.File != scanner.SettingsFile {
			kept = append(kept, f)
		}
	}
	fresh, err := scanRepositorySettings(repo, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: post-fix settings re-audit failed: %v\n", err)
		return findings
	}
	return append(kept, fresh...)
}

// scanRepositorySettings fetches the repo's GitHub-side configuration and runs
// the settings audit rules. Returns the resulting findings (file-path =
// SettingsFile, line = 0) or an error if the GitHub API call(s) fail.
func scanRepositorySettings(repo, token string) ([]scanner.Finding, error) {
	owner, name, err := parseOwnerRepo(repo)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := vcs.NewBareGitHubClient()
	settings, err := client.FetchRepositorySettings(ctx, token, owner, name, "", fmt.Sprintf("https://github.com/%s/%s", owner, name))
	if err != nil {
		return nil, err
	}
	return scanner.ScanRepositorySettings(*settings), nil
}

// cloneRemoteRepo clones the resolved target into a fresh temp directory and
// returns its path. The URL is composed from the target host/owner/name so
// both GitHub (github.com) and GitLab (gitlab.com or self-hosted) work via
// the same `git clone --depth 1` invocation.
func cloneRemoteRepo(t gitTarget) (string, error) {
	repoURL := fmt.Sprintf("https://%s/%s/%s.git", t.Host, t.Owner, t.Name)

	tempDir, err := os.MkdirTemp("", "pipefort-scan-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	gitCmd := exec.Command("git", "clone", "--depth", "1", repoURL, tempDir)
	gitCmd.Stdout = nil
	gitCmd.Stderr = os.Stderr

	if err := gitCmd.Run(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("git clone failed: %w", err)
	}

	return tempDir, nil
}

// applyGitLabMRFix opens (or reuses) one MR per fixable GitLab CI YAML
// finding. The GitLab project ID is supplied as a URL-encoded
// "namespace/name" path so GitLab's API endpoints accept it directly without
// a separate numeric-id lookup.
func applyGitLabMRFix(t gitTarget, token string, findings []scanner.Finding) {
	client := vcs.NewBareGitLabClient(t.Host)
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", t.Owner, t.Name))

	if dryRun {
		fmt.Println("\n--- GITLAB MR FIX (DRY RUN) ---")
	} else {
		fmt.Println("\n--- GITLAB MR FIX ---")
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if !vcs.IsAutoFixableWorkflowRule(f.RuleID) || f.File == "" {
			continue
		}
		key := string(f.RuleID) + "|" + f.File
		if seen[key] {
			continue
		}
		seen[key] = true

		if dryRun {
			fmt.Printf("  → would open MR for %s in %s\n", f.RuleID, f.File)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := client.FixWorkflow(ctx, token, vcs.RepoCoord{
			Owner: t.Owner, Name: t.Name, ID: projectPath,
		}, "main", f.File, f.RuleID)
		cancel()
		switch {
		case err == nil:
			tag := "✓"
			if res.Reused {
				tag = "↺"
			}
			fmt.Printf("  %s %s: %s\n", tag, f.RuleID, res.URL)
		case err == vcs.ErrChangeRequestNoChange:
			fmt.Printf("  - %s: no change needed (already remediated)\n", f.RuleID)
		default:
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", f.RuleID, err)
		}
	}
}

// scanGitLabProjectSettings fetches and scans one GitLab project's settings.
func scanGitLabProjectSettings(t gitTarget, token string) ([]scanner.Finding, error) {
	client := vcs.NewBareGitLabClient(t.Host)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	coord := vcs.RepoCoord{Owner: t.Owner, Name: t.Name, ID: fmt.Sprintf("%s/%s", t.Owner, t.Name)}
	htmlURL := fmt.Sprintf("https://%s/%s/%s", t.Host, t.Owner, t.Name)
	return client.AuditSettings(ctx, token, coord, "", htmlURL)
}

// applyGitLabSettingsFix applies the auto-fixable GitLab settings findings via
// the projects API, printing each action. Re-audits afterward so the final
// report drops fixed findings.
func applyGitLabSettingsFix(t gitTarget, token string, findings []scanner.Finding) []scanner.Finding {
	client := vcs.NewBareGitLabClient(t.Host)
	coord := vcs.RepoCoord{Owner: t.Owner, Name: t.Name, ID: fmt.Sprintf("%s/%s", t.Owner, t.Name)}

	var settingsFindings []scanner.Finding
	for _, f := range findings {
		if f.File == scanner.SettingsFile && f.RuleID != "" {
			settingsFindings = append(settingsFindings, f)
		}
	}
	if len(settingsFindings) == 0 {
		return findings
	}

	if dryRun {
		fmt.Println("\n--- GITLAB SETTINGS FIX (DRY RUN) ---")
	} else {
		fmt.Println("\n--- GITLAB SETTINGS FIX ---")
	}
	for _, f := range settingsFindings {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		action, err := client.FixSetting(ctx, token, coord, "", f.RuleID, dryRun)
		cancel()
		switch {
		case err == vcs.ErrSettingsNotSupported:
			fmt.Fprintf(os.Stderr, "  - %s: no auto-fix available\n", f.RuleID)
		case err != nil:
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", f.RuleID, err)
		default:
			prefix := "✓"
			if dryRun {
				prefix = "→"
			}
			fmt.Printf("  %s %s\n", prefix, action.Description)
		}
	}

	if dryRun {
		return findings
	}
	// Re-audit to drop fixed settings findings; keep non-settings findings.
	var kept []scanner.Finding
	for _, f := range findings {
		if f.File != scanner.SettingsFile {
			kept = append(kept, f)
		}
	}
	fresh, err := scanGitLabProjectSettings(t, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: post-fix GitLab settings re-audit failed: %v\n", err)
		return findings
	}
	return append(kept, fresh...)
}

func shouldFail(findings []scanner.Finding, threshold string) bool {
	threshold = strings.ToUpper(threshold)
	if threshold == "NONE" {
		return false
	}

	severityWeight := map[scanner.Severity]int{
		scanner.SeverityInfo:   1,
		scanner.SeverityLow:    2,
		scanner.SeverityMedium: 3,
		scanner.SeverityHigh:   4,
	}

	thresholdWeight, exists := map[string]int{
		"INFO":   1,
		"LOW":    2,
		"MEDIUM": 3,
		"HIGH":   4,
	}[threshold]

	if !exists {
		// Default to MEDIUM if invalid value passed
		thresholdWeight = 3
	}

	for _, f := range findings {
		weight := severityWeight[f.Severity]
		if weight >= thresholdWeight {
			return true
		}
	}

	return false
}
