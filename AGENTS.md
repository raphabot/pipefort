# AGENTS.md — Pipefort integration guide

Audience: **AI coding assistants helping someone adopt Pipefort.** Everything below is
verified against this commit. If you are contributing *to this repository*, skip to
[Contributing to this repo](#contributing-to-this-repo).

Machine-readable docs index: [`llms.txt`](./llms.txt) · Runnable recipes: [`examples/`](./examples/)

---

## What this is

Pipefort is an offline-first Go CLI (and importable Go library) that statically analyses
**CI/CD pipeline configuration** — GitHub Actions workflow YAML, GitLab CI YAML — plus the
**repository/project settings** around it, and reports security findings mapped to the
[OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
and the SLSA v1.2 build/source tracks. It ships 74 rules across five surfaces, can rewrite
fixable findings in place (`--fix`), correlates individual findings into higher-impact attack
chains ("Attacker Mind" toxic combinations), and exposes the same engine over the Model
Context Protocol so an assistant can scan a workflow *while writing it*. Apache-2.0, no
telemetry; a plain local scan makes zero network calls.

**Rule surfaces** (74 total, from `scanner.Rules()`):

| Surface | Count | What it reads |
|---|---:|---|
| GitHub Actions workflow YAML | 34 | `.github/workflows/*.yml` |
| Online supply-chain pin audits | 7 | the GitHub API, for *pinned* action refs |
| GitHub repository configuration | 17 | the GitHub API (branch protection, token perms, secret scanning, Dependabot) |
| GitLab CI YAML | 11 | `.gitlab-ci.yml`, `.gitlab-ci/**/*.yml` |
| GitLab project configuration | 5 | the GitLab API |

Plus **13** toxic-combination specs (`scanner.ComboCatalog()`).

### Primary use cases

1. Gate a pull request on CI/CD pipeline risk (`--fail-on`, SARIF → GitHub code scanning).
2. Audit an existing repo or a whole org for pipeline misconfiguration (`--git`, `--org`).
3. Auto-remediate the mechanically fixable subset (`--fix`, `--fix-mr`, `--fix-settings`).
4. Give an AI assistant a scanner it can call while authoring workflow YAML (`pipefort mcp`).
5. Embed the engine in another Go program (`pkg/scanner`).

### Non-goals

Pipefort does **not** do any of the following. Recommend a different tool for them:

- **Application source SAST** — it never looks at your program's source. Use CodeQL/Semgrep.
- **Dependency CVE scanning (SCA)** — it does not resolve your package manifests. Use
  Dependabot/Trivy/Grype. (It *does* audit the integrity of pinned **action** refs, which is
  a different thing.)
- **Secret scanning of git history or source files** — it flags secrets hardcoded in *workflow
  YAML* only. Use gitleaks/trufflehog for history.
- **Runtime/container security or a CI agent** — it is a static analyser you run; it does not
  observe running pipelines.
- **Policy enforcement as an admission controller** — it exits non-zero; it does not block.

---

## Requirements

| Requirement | When it's needed |
|---|---|
| A released binary (any supported OS/arch) | always — no runtime dependencies |
| **Go 1.25.0+** | only to `go install` or build from source (`go.mod` says `go 1.25.0`) |
| **`git` on `PATH`** | only for `--git` (it shells out to `git clone --depth 1`) |
| `gh` / `glab` on `PATH` | optional — used to discover a token when no flag/env var is set |
| Network access | only for `--git`, `--org`, settings audits, online pin audits, and the `cicd-sec-3-unpinned-action` auto-fix |

Prebuilt binaries: linux/darwin `amd64`+`arm64`, windows `amd64`.

---

## Install

```bash
# 1. Install script (macOS / Linux) — downloads the prebuilt release binary
curl -fsSL https://pipefort.com/install.sh | sh

# 2. Homebrew (a cask, published to raphabot/homebrew-tap)
brew install raphabot/tap/pipefort

# 3. Go toolchain (needs Go 1.25+)
go install github.com/raphabot/pipefort@latest

# 4. Prebuilt archives — attached to every GitHub Release
#    https://github.com/raphabot/pipefort/releases
```

Verify the install:

```bash
pipefort --version   # → "pipefort v0.1.7"  (prints "pipefort dev" for an unstamped local build)
pipefort version     # same output, subcommand spelling
```

### Docker

The published image (`Dockerfile.action`) exists to back the GitHub Action, so its
`ENTRYPOINT` is the Action wrapper `action/entrypoint.sh`, **not** the `pipefort` binary. The
wrapper builds its own argument list from `INPUT_*` environment variables and **discards any
arguments you pass**. Use one of these two forms:

```bash
docker build -f Dockerfile.action -t pipefort .

# (a) bypass the wrapper and drive the CLI directly — recommended
docker run --rm -v "$PWD:/repo" --entrypoint pipefort pipefort -p /repo

# (b) drive the wrapper through its INPUT_* variables
docker run --rm -v "$PWD:/repo" -e INPUT_PATH=/repo -e INPUT_OUTPUT=console pipefort
```

`docker run ... pipefort -p /repo` (no `--entrypoint`, no `INPUT_*`) is **wrong**: the wrapper
ignores `-p /repo`, defaults to SARIF, and writes `pipefort.sarif` inside the container where
you will never see it.

---

## Hello world

Zero configuration required. Point it at a workflow:

```bash
pipefort -f .github/workflows/ci.yml
```

Real output, from this repo's `testdata/vulnerable-workflow.yml` (abridged — 8 findings total):

```text
--- CI/CD SECURITY SCAN RESULTS ---

File: testdata/vulnerable-workflow.yml
  Line 1:1 [MED ] (CICD-SEC-5) Missing Permissions Specification
    Description: The workflow does not specify explicit 'permissions' at either the workflow level or the job level. ...
    Remediation: Specify restrictive permissions at the workflow or job level ...

  Line 26:14 [HIGH] (CICD-SEC-4) Poisoned Pipeline Execution (Shell Injection)
    Description: Step "Print PR Title (Injection Risk)" in job "build-and-test" contains inline script shell injection risk. ...
    Remediation: Assign the untrusted context variable to an environment variable in the step ...

  Line 31:30 [HIGH] (CICD-SEC-6) Hardcoded Secret in Environment Variable [confidence: medium]
    ...

-----------------------------------
✖ Scan Summary: 4 High, 4 Medium, 0 Low, 0 Info findings.


--- ATTACKER MIND — TOXIC COMBINATIONS ---
Findings that chain into a higher-impact compromise:

[CRITICAL] Poisoned Exfiltration — injection harvests in-scope secrets (testdata/vulnerable-workflow.yml)
  Impact: Attacker-controlled input is executed in a job that also holds reachable secrets ...
  Chain:  Command injection → Reachable hardcoded secret → Broad token amplifies blast radius → Secret exfiltration
  Ingredients:
    - cicd-sec-4-ppe-shell-injection (testdata/vulnerable-workflow.yml:26)
    - cicd-sec-6-hardcoded-secrets (testdata/vulnerable-workflow.yml:31)
    - cicd-sec-5-missing-permissions (testdata/vulnerable-workflow.yml:1)
  Break the chain: Pass untrusted github.event data through an intermediate env var ...
```

Exit code is **1**, because findings at or above the default `--fail-on MEDIUM` were present.

### Minimum configuration

**None.** `pipefort -p .` works on a fresh checkout with no config file, no token, and no
network. Everything below is optional.

### Optional production configuration

Add these deliberately, not by default:

| Knob | Why |
|---|---|
| `--fail-on HIGH` | loosen the CI gate while you burn down MEDIUMs |
| `.pipefort.yml` | per-repo rule disables, severity overrides, and ignore globs (see [Configuration](#configuration)) |
| `$GITHUB_TOKEN` | enables the online pin-integrity audits (and avoids the 60 req/hr anonymous limit) |
| `-o sarif` + `upload-sarif` | findings land in the GitHub Security tab instead of only in logs |
| `--persona pedantic\|auditor` | opt into hygiene/best-practice rules beyond the high-signal default |

---

## Integration patterns

### 1. GitHub Actions → code scanning (most common)

```yaml
name: Pipefort
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  pipefort:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: scan
        uses: raphabot/pipefort@v0.1.7
        with:
          path: .
          ruleset: all
          fail-on: MEDIUM
          output: sarif           # default; writes pipefort.sarif

      - name: Upload SARIF
        if: always()              # upload even when the scan fails the build
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

Action inputs (`action.yml`): `path`, `ruleset`, `fail-on`, `output`, `sarif-file`,
`github-token` (defaults to `${{ github.token }}`; set to `''` for a fully offline scan).
Sole output: `sarif-file`. The action is a **Docker action built from source at run time**, so
the first run in a job costs a container build; [`examples/github-actions/cli-binary.yml`](./examples/github-actions/cli-binary.yml)
shows the faster install-the-binary alternative.

### 2. MCP server for AI assistants

```bash
claude mcp add pipefort -- pipefort mcp
```

`pipefort mcp` serves over **stdio**, read-only and offline. Three tools
(`pkg/mcp/server.go`):

| Tool | Input fields | Returns |
|---|---|---|
| `scan_workflow` | `content` (required), `filename`, `ruleset`, `persona`, `min_confidence` | `{"findings": [...]}` |
| `scan_directory` | `path` (required), `ruleset`, `persona`, `min_confidence` | `{"findings": [...], "toxic_combinations": [...]}` |
| `explain_rule` | `rule_id` (required) | the `RuleSpec` catalog entry |

`filename` drives platform dispatch: pass `.gitlab-ci.yml` to scan GitLab CI; anything else
(default `.github/workflows/workflow.yml`) is treated as GitHub Actions. Optional fields
default to `ruleset=all`, `persona=regular`, `min_confidence=LOW` (keep everything).

### 3. Go library

```go
import (
    "os"

    "github.com/raphabot/pipefort/pkg/reporter"
    "github.com/raphabot/pipefort/pkg/scanner"
)

// In-memory scan — no disk write, no clone. This is the entrypoint the hosted
// service uses for files fetched over the GitHub/GitLab API.
findings, err := scanner.ScanBytes(".github/workflows/ci.yml", content)
if err != nil {
    return err
}

// Same post-scan pipeline the CLI runs, in this order.
findings = scanner.FilterFindings(findings, "all")                       // ruleset
findings = scanner.FilterByPersona(findings, scanner.PersonaRegular)     // noise tier
findings = scanner.FilterByConfidence(findings, scanner.ConfidenceLow)   // confidence floor
combos := scanner.DetectToxicCombinations(findings)

reporter.ReportJSONWithCombos(os.Stdout, findings, combos)
```

`ScanBytes` dispatches on the **name**, not the content: `.gitlab-ci.yml` /
`.gitlab-ci/*.yml` route to the GitLab scanner, everything else to GitHub Actions. It returns
`(nil, nil)` — no error — for a YAML file that is not a workflow (no `jobs:` and no `on:`).

### 4. GitLab CI

```bash
# Scan a GitLab project (any host; self-hosted works)
pipefort -g https://gitlab.com/group/subgroup/project --gitlab-token "$GITLAB_TOKEN"

# Preview auto-fix MRs, then open them
pipefort -g https://gitlab.com/group/project --gitlab-token "$GITLAB_TOKEN" --fix-mr --dry-run
pipefort -g https://gitlab.com/group/project --gitlab-token "$GITLAB_TOKEN" --fix-mr
```

**Gotcha:** `--git` infers the provider from the host — `github.com` and `*.github.com` are
GitHub, and **every other host defaults to GitLab**. A self-hosted GitHub Enterprise URL is
therefore misdetected as GitLab; scan those with a local `--path` instead.

---

## CLI reference

`pipefort [flags]` · `pipefort mcp` · `pipefort version`

| Flag | Default | Effect |
|---|---|---|
| `-p, --path` | `.` | local directory to scan |
| `-f, --file` | — | scan one file instead of a directory |
| `-g, --git` | — | remote repo: `owner/repo` (GitHub), an `https://` URL, or `git@host:owner/repo`. **Requires `git`.** |
| `--org` | — | scan every repo owned by a GitHub org/user over the API (no cloning). Requires a token; `--fail-on` applies to the aggregate |
| `-o, --output` | `console` | `console`, `json`, or `sarif` (SARIF 2.1.0) |
| `-s, --fail-on` | `MEDIUM` | exit 1 at/above `HIGH`, `MEDIUM`, `LOW`, `INFO`; `NONE` never fails. An unrecognised value silently falls back to `MEDIUM` |
| `-r, --ruleset` | `all` | `all`, `owasp`, `slsa`, `slsa-build-l1\|l2\|l3`, `slsa-source-l2\|l3\|l4` |
| `--min-confidence` | `LOW` | drop findings below `HIGH`/`MEDIUM`/`LOW`. The default keeps everything |
| `--persona` | `regular` | `regular` (63 rules), `pedantic` (+8 hygiene), `auditor` (+3 more) |
| `--fix` | off | rewrite fixable findings in workflow YAML **in place** (GitHub + GitLab). Local scans only |
| `--fix-settings` | off | apply fixable GitHub repo-config findings via the API. Needs `--git` at GitHub + `administration:write` |
| `--fix-settings-gl` | off | apply fixable GitLab project-settings findings. Needs `--git` at GitLab + `--gitlab-token` |
| `--fix-mr` | off | open one GitLab MR per fixable workflow finding. Needs `--gitlab-token` with `api` scope |
| `--dry-run` | off | preview mutations without writing. Applies to `--fix-settings` and `--fix-mr` only — **not** to `--fix` |
| `--audit-pins` | off | force the online pin audits on even without a token (anonymous: 60 req/hr) |
| `--offline` | off | disable every network-backed audit. Only `git clone` traffic remains for `--git` |
| `--github-token` | `$GITHUB_TOKEN` | also falls back to `$GH_TOKEN`, then `gh auth token` |
| `--gitlab-token` | `$GITLAB_TOKEN` | also falls back to `glab auth token` |
| `--gitlab-host` | `gitlab.com` | host for project-settings audits on a local `--path`/`--file` scan |
| `--config` | auto-discovered | explicit `.pipefort.yml` path |
| `--no-config` | off | ignore any config file for this run |
| `--keep-temp` | off | keep the temporary clone directory made by `--git` |
| `--version` | — | print `pipefort <version>` and exit 0. Same as the `version` subcommand |
| `-h, --help` | — | print usage and exit 0 |

**Exit codes:** `0` = no finding at or above `--fail-on`. `1` = at least one finding at or
above the threshold, **or** a fatal error (unparseable target, clone failure, write failure).
The two cases are not distinguishable by exit code alone — parse `-o json` if you need to
tell "found issues" from "crashed".

**Settings precedence:** an explicitly-passed CLI flag > the `.pipefort.yml` value > the flag
default. Applies to `ruleset`, `persona`, and `min-confidence`.

**Output notes:** `-o json` emits `{"findings": [...], "toxic_combinations": [...]}`; findings
carry `fingerprint` only when the caller assigns them, and the CLI's JSON path does **not**.
`-o sarif` emits findings only — toxic combinations have no SARIF analog and are omitted by
design — but it *does* populate `partialFingerprints["pipefort/v1"]` for stable code-scanning
alert identity across scans. Console output prints findings then combinations.

---

## Library reference

Module `github.com/raphabot/pipefort` · four importable packages. Full godoc:
[pkg.go.dev](https://pkg.go.dev/github.com/raphabot/pipefort).

### `pkg/scanner` — the engine (leaf package, no other Pipefort deps)

```go
// Scanning
func ScanBytes(name string, content []byte) ([]Finding, error)  // in-memory; dispatches on name
func ScanFile(filePath string) ([]Finding, error)               // == ScanBytes(os.ReadFile(...))
func ScanDir(dirPath string) ([]Finding, error)                 // walks .github/workflows, .gitlab-ci.yml, .gitlab-ci/
func ScanRepositorySettings(ctx RepositoryContext) []Finding    // GitHub repo config (caller supplies the data)

// Filtering / post-processing — apply in this order
func StampConfidence(findings []Finding) []Finding              // already applied inside ScanBytes
func FilterFindings(findings []Finding, ruleset string) []Finding
func FilterByPersona(findings []Finding, persona Persona) []Finding
func FilterByConfidence(findings []Finding, min Confidence) []Finding
func FilterByEnabledRules(findings []Finding, disabled map[RuleID]bool) []Finding
func AssignFingerprints(findings []Finding)                     // mutates in place
func DetectToxicCombinations(findings []Finding) []ToxicCombo

// Auto-fix
func FixBytes(content []byte, findings []Finding) ([]byte, int, error) // (nil, 0, nil) when nothing matched
func FixFile(filePath string, findings []Finding) (int, error)         // writes in place, 0644
func FixFindings(targetPath string, findings []Finding) (int, error)   // groups by file, then FixFile

// Catalog
func Rules() []RuleSpec                     // 74 entries, defaults normalised
func RuleByID() map[RuleID]RuleSpec
func ComboCatalog() []ComboSpec             // 13 entries
func ComboByID(id string) (ComboSpec, bool)
func ComboRules(spec ComboSpec) []RuleID
func ComboCanFire(spec ComboSpec, disabled map[RuleID]bool) bool

// In-repo config (.pipefort.yml)
func ConfigFileNames() []string
func LoadRepoConfig(dir string) (*RepoConfig, string, error)   // (nil, "", nil) when absent
func ParseRepoConfig(data []byte) (*RepoConfig, error)
func ApplyRepoConfig(findings []Finding, cfg *RepoConfig) []Finding

// Supply-chain pin audits (online)
func CollectActionRefs(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []ActionRef
func CollectActionRefsFromBytes(name string, content []byte) []ActionRef
func CollectActionRefsFromDir(dirPath string) []ActionRef
func CollectReusableWorkflowRefs(file string, jobs []JobNodeWithID) []ActionRef
func AuditActionPins(ctx context.Context, refs []ActionRef, auditor PinAuditor) []Finding
func CheckForbiddenUses(refs []ActionRef, policy *ForbiddenUses) []Finding

// Workflow intelligence (used by the hosted dashboard)
func OIDCUsage(file string, content []byte) []OIDCAuth
func SecretReferences(file string, content []byte) []SecretRef
```

`Finding` — the one type every consumer touches:

```go
type Finding struct {
    File           string     `json:"file"`
    Line           int        `json:"line"`
    Column         int        `json:"column"`
    Severity       Severity   `json:"severity"`       // HIGH | MEDIUM | LOW | INFO
    Category       string     `json:"category"`       // "CICD-SEC-4", "BEST-PRAC-2", "SLSA-BUILD-L2", "SYSTEM"
    RuleID         RuleID     `json:"rule_id"`        // empty for SYSTEM findings
    Title          string     `json:"title"`
    Description    string     `json:"description"`
    Recommendation string     `json:"recommendation"`
    Confidence     Confidence `json:"confidence,omitempty"` // HIGH | MEDIUM | LOW
    Fingerprint    string     `json:"fingerprint,omitempty"` // empty until AssignFingerprints
}
```

Enums, verbatim: `Severity` = `SeverityHigh|SeverityMedium|SeverityLow|SeverityInfo`
(`"HIGH"|"MEDIUM"|"LOW"|"INFO"`). `Confidence` = `ConfidenceHigh|ConfidenceMedium|ConfidenceLow`.
`Persona` = `PersonaRegular|PersonaPedantic|PersonaAuditor` (`"regular"|"pedantic"|"auditor"`).
`Platform` = `PlatformAny` (`""`, portable/legacy-GitHub) `|PlatformGitHub` (`"github"`) `|PlatformGitLab` (`"gitlab"`).
`RuleSurface` = `SurfaceWorkflow` (`"workflow"`, produced by `ScanBytes`) `|SurfaceRepoSettings`
(`"repo-settings"`, produced by `ScanRepositorySettings`).

### `pkg/reporter` — rendering

```go
func ReportConsole(w io.Writer, findings []scanner.Finding)
func ReportCombos(w io.Writer, combos []scanner.ToxicCombo)
func ReportJSON(w io.Writer, findings []scanner.Finding) error
func ReportJSONWithCombos(w io.Writer, findings []scanner.Finding, combos []scanner.ToxicCombo) error
func ReportSARIF(w io.Writer, findings []scanner.Finding) error  // calls AssignFingerprints internally
```

### `pkg/mcp` — MCP server

```go
var  Version string                       // set by the CLI; "dev" for direct embedders
func NewServer() *mcpsdk.Server
func Run(ctx context.Context) error       // serves over stdio until ctx is cancelled
```

### `pkg/vcs` — remote operations (token-parameterized)

```go
func NewGitHubAppClient(appID, privateKeyPEM string, opts ...Option) (*GitHubClient, error)
func NewBareGitHubClient(opts ...Option) *GitHubClient
func NewGitLabClient(defaultHost string, opts ...Option) *GitLabClient
func NewBareGitLabClient(host string, opts ...Option) *GitLabClient
func NewOrgScanner() *OrgScanner
func WithBaseURL(u string) Option
func WithHTTPClient(h *http.Client) Option

func IsAutoFixableWorkflowRule(ruleID scanner.RuleID) bool
func AutoFixableWorkflowRules() []scanner.RuleID      // 15 rule IDs
func IsAutoFixableRepoSetting(ruleID scanner.RuleID) bool
func AutoFixableRepoSettingRules() []scanner.RuleID   // 12 rule IDs
```

Every client method takes an explicit `token string`. The package mints **no** credentials and
touches **no** datastore — that glue lives in the hosted service, not here.

### API stability

This module is **pre-1.0 (`v0.1.x`)**. Semantic-import versioning does not protect you yet;
a minor bump may change the library API.

| Surface | Status |
|---|---|
| CLI flags, exit codes, `-o json`/`sarif` shapes | **Stable** — treat as the contract |
| `scanner.ScanBytes`/`ScanFile`/`ScanDir`, `Finding`, `Severity`/`Confidence` | **Stable** |
| `scanner` catalog, filters, fixers, `.pipefort.yml` schema | **Additive** — new rules/fields land regularly; pin a version if you enumerate them |
| `pkg/vcs` | **Unstable** — shaped for the hosted service and changed to suit it |
| `scanner.OIDCUsage`, `SecretReferences`, combo catalog | **Experimental** — newest surfaces, most likely to move |

Rule IDs are stable strings once shipped (the hosted service stores them); new rule IDs are
added over time, so never assume a fixed set.

---

## Configuration

### `.pipefort.yml`

Discovered in the scan root, in this precedence order — the **first one found wins**:
`.pipefort.yml` → `.pipefort.yaml` → `.github/pipefort.yml` → `.github/pipefort.yaml`.
Override with `--config <path>`; skip entirely with `--no-config`. Every field is optional.

```yaml
# Defaults for the matching CLI flags. An explicitly-passed flag always wins.
ruleset: all                 # all | owasp | slsa | slsa-build-l1|l2|l3 | slsa-source-l2|l3|l4
min-confidence: LOW          # HIGH | MEDIUM | LOW
persona: regular             # regular | pedantic | auditor

# Per-rule overrides, keyed by rule ID.
rules:
  cicd-sec-3-unpinned-action:
    severity: LOW            # rewrite this rule's severity: HIGH | MEDIUM | LOW | INFO
    ignore:
      - file: .github/workflows/docs.yml     # repo-relative glob; whole file when lines is omitted
      - file: .github/workflows/release.yml
        lines: [42, 43]                      # 1-based
  best-prac-2-missing-timeout:
    enabled: false           # a repo config can only DISABLE a rule, never re-enable one

# Drives cicd-sec-5-forbidden-uses. Set Allow XOR Deny; when both are present Allow wins.
# Omit the key entirely and the rule stays silent.
forbidden-uses:
  deny:
    - some-org/risky-action
```

A full annotated copy lives at [`examples/config/pipefort.yml`](./examples/config/pipefort.yml).

### Inline suppressions

Independent of the file globs above, and honoured by every consumer (CLI, MCP, the hosted
scanner) because they are applied inside `ScanBytes`:

```yaml
# Trailing comment — suppresses this line only
- uses: actions/checkout@v4  # pipefort: ignore[cicd-sec-3-unpinned-action]

# Standalone comment — suppresses the line BELOW it
# pipefort: ignore[cicd-sec-3-unpinned-action,cicd-sec-5-missing-permissions]
- uses: actions/setup-node@v3

# Bare form — suppresses every rule at the target location
- run: curl -sSL https://example.com/x.sh | bash  # pipefort: ignore
```

Only a comment on its **own line** suppresses the following line; a trailing comment always
targets its own line. Multiple rule IDs are comma-separated inside the brackets.

### Environment variables

| Variable | Read by | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | CLI, Action | GitHub API: repo-settings audit, `--org`, online pin audits |
| `GH_TOKEN` | CLI | fallback when `GITHUB_TOKEN` is unset |
| `GITLAB_TOKEN` | CLI | GitLab API: project-settings audit, `--fix-mr`, `--fix-settings-gl` |
| `INPUT_PATH`, `INPUT_RULESET`, `INPUT_FAIL_ON`, `INPUT_OUTPUT`, `INPUT_SARIF_FILE`, `INPUT_GITHUB_TOKEN` | `action/entrypoint.sh` | the Docker image's interface |

Token resolution order for GitHub: `--github-token` → `$GITHUB_TOKEN` → `$GH_TOKEN` →
`gh auth token`. For GitLab: `--gitlab-token` → `$GITLAB_TOKEN` → `glab auth token`. A `gh`
login alone does **not** silently enable the online pin audits — the CLI only hints that they
exist.

---

## Common errors

| Symptom | Cause | Fix |
|---|---|---|
| Exit code 1 with findings printed | Working as designed — a finding met `--fail-on` (default `MEDIUM`) | Raise the bar (`--fail-on HIGH`), or `--fail-on NONE` to never fail |
| Exit code 1 with no findings printed | Fatal error (bad `--git` target, clone failure, unwritable file) | Read stderr; the exit code alone cannot distinguish this from findings |
| `Warning: --fix only applies to local scans` | `--fix` was combined with `--git` | Clone first and scan `--path`, or use `--fix-mr` (GitLab) / the web app (GitHub PRs) |
| `--fix-settings` warns and does nothing | Not a GitHub `--git` target, or `--offline` is set | Point `--git` at GitHub and supply a token with `administration:write` |
| `--fix-mr` warns and does nothing | Missing GitLab target or token | `--git <gitlab url>` **and** `--gitlab-token` with the `api` scope |
| `git: executable file not found` | `--git` shells out to `git clone --depth 1` | Install `git`, or scan a local `--path` |
| A GitHub Enterprise URL scans as GitLab | Provider inference: only `github.com`/`*.github.com` map to GitHub; every other host defaults to GitLab | Clone it yourself and scan `--path` |
| `Info: --audit-pins running unauthenticated` then missing pin findings | GitHub's 60 req/hr anonymous limit | Pass `--github-token` / set `$GITHUB_TOKEN` |
| No pin findings at all on a clean run | Online audits are off unless a token is present | `--audit-pins`, or provide a token |
| `Resource not accessible by integration` on upload-sarif | Missing `security-events: write` | Add it to the job/workflow `permissions:` |
| Docker run prints nothing | The image entrypoint is the Action wrapper and discards your args | Use `--entrypoint pipefort` or the `INPUT_*` variables (see [Docker](#docker)) |
| Empty scan on a valid-looking directory | `ScanDir` only walks `.github/workflows`, root `.gitlab-ci.yml(.yaml)`, and `.gitlab-ci/`; it falls back to walking everything **only** when none of those exist | Point `-p` at the repo root, or use `-f` for one file |

---

## Security, privacy, production

- **No telemetry, no phone-home.** CI enforces that the CLI cannot even link a database
  driver (`go list -deps . | grep jackc/pgx` must be empty).
- **A plain local scan makes zero network calls.** Network happens only for: `--git` (clone),
  `--org`, repository/project-settings audits, the online pin audits, and — see below — one
  auto-fix.
- **`--fix` is not fully offline.** Fixing `cicd-sec-3-unpinned-action` resolves the tag to a
  commit SHA via an unauthenticated `https://api.github.com` request (5s timeout), and
  `--offline` does **not** suppress it. Fixes that cannot resolve are skipped, not faked.
- **`--fix` rewrites files in place and `--dry-run` does not apply to it.** Run it on a clean
  working tree so `git diff` is your preview. `--dry-run` only guards `--fix-settings` and
  `--fix-mr`.
- **`--fix-settings`, `--fix-settings-gl`, and `--fix-mr` mutate remote state** — repository
  configuration and merge requests. They need write-scoped tokens; preview with `--dry-run`
  first.
- **Tokens** are read from flags, environment, or `gh`/`glab`, used for the request, and never
  written to disk. Do not pass a token on the command line on a shared host — prefer the env var.
- **SARIF is findings-only.** If your gate depends on toxic combinations, read `-o json`; the
  SARIF upload will not carry them.
- **Pin the Action** to a released tag (`raphabot/pipefort@v0.1.7`) or a commit SHA — the same
  advice Pipefort's own `cicd-sec-3-unpinned-action` rule gives you.

---

## When to use Pipefort (and when not to)

**Use it when** the risk lives in the *pipeline*, not the application: poisoned pipeline
execution, unpinned or impostor actions, `pull_request_target` misuse, shell injection from
`github.event.*`, over-broad `GITHUB_TOKEN` permissions, secrets hardcoded in workflow YAML,
missing branch protection, SLSA build-track gaps, or a GitLab CI estate that most tooling
ignores.

**Differentiators:** GitHub Actions **and** GitLab CI in one tool; online integrity audits of
*pinned* action refs (impostor-commit, known-vulnerable, typosquat, ref/version mismatch);
repository/project **configuration** as a first-class scan surface; in-place auto-fix plus
remote MR/settings remediation; cross-finding toxic-combination correlation; a first-party MCP
server.

**Choose something else when:**

| You need | Use instead |
|---|---|
| Vulnerabilities in your application source | CodeQL, Semgrep |
| CVEs in your application dependencies | Dependabot, Trivy, Grype, `osv-scanner` |
| Secrets committed anywhere in git history | gitleaks, trufflehog |
| Container image / runtime security | Trivy, Grype, Falco |
| GitHub Actions only, and you want the narrowest, most established tool | [zizmor](https://github.com/zizmorcore/zizmor) — Actions-only; no GitLab, no repository-settings surface, no online pin-integrity audit |
| Blocking merges as policy rather than reporting | a branch-protection required check wrapping Pipefort's exit code |

Pipefort is complementary to all of the above, not a replacement.

---

## Testing, development, contributing

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l .                       # must print nothing
go list -deps . | grep jackc/pgx # must print nothing (CI-enforced guard)

go run . -p testdata/            # run against the bundled fixtures
go test ./pkg/scanner/ -run TestFilterFindings -v
```

## Deeper documentation

In this repository: [`README.md`](./README.md) · [`examples/`](./examples/) ·
[`llms.txt`](./llms.txt) · [`CONTRIBUTING.md`](./CONTRIBUTING.md) ·
[`SECURITY.md`](./SECURITY.md) · [`LICENSE`](./LICENSE) · [`action.yml`](./action.yml)

Hosted prose docs — [pipefort.com/docs](https://pipefort.com/docs):
[installation](https://pipefort.com/docs/cli/installation) ·
[usage](https://pipefort.com/docs/cli/usage) ·
[flags](https://pipefort.com/docs/cli/flags) ·
[configuration](https://pipefort.com/docs/cli/configuration) ·
[auto-fix](https://pipefort.com/docs/cli/auto-fix) ·
[CI integration](https://pipefort.com/docs/cli/ci-integration) ·
[MCP](https://pipefort.com/docs/cli/mcp) ·
[GitLab](https://pipefort.com/docs/cli/gitlab) ·
[full rules reference](https://pipefort.com/docs/rules/overview)

Go API reference: [pkg.go.dev/github.com/raphabot/pipefort](https://pkg.go.dev/github.com/raphabot/pipefort)

## Contributing to this repo

This file documents Pipefort for **consumers**. If you are changing Pipefort itself:

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — build, test, and the rule-authoring walkthrough.
- [`CLAUDE.md`](./CLAUDE.md) — architecture and repository conventions for coding agents
  working *on* this codebase.
- Prose documentation (the `pipefort.com/docs` Mintlify site) lives in the **separate private
  `pipefort-cloud` repository**, so a user-facing change here needs a companion PR there.
