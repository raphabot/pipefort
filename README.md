# Pipefort

**Scan your CI/CD pipelines for the OWASP Top 10 CI/CD security risks.** Pipefort
is a fast, offline-first CLI that inspects GitHub Actions and GitLab CI pipelines
— 74 rules spanning workflow YAML, online action-pin supply-chain audits, SLSA
build-track coverage, and repository/project configuration — with auto-fix and
cross-finding "Attacker Mind" toxic-combination detection.

> **Using an AI coding assistant?** Point it at [AGENTS.md](./AGENTS.md) — a complete,
> verified integration guide. Machine-readable docs index: [llms.txt](./llms.txt).
> Copy-pasteable recipes: [examples/](./examples/).

[![CI](https://github.com/raphabot/pipefort/actions/workflows/ci.yml/badge.svg)](https://github.com/raphabot/pipefort/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

## Install

```bash
# Install script (macOS / Linux) — downloads the prebuilt release binary
curl -fsSL https://pipefort.com/install.sh | sh

# Homebrew
brew install raphabot/tap/pipefort

# Go toolchain (needs Go 1.25+)
go install github.com/raphabot/pipefort@latest
```

Prebuilt archives for Linux, macOS, and Windows (amd64/arm64) are attached to
each [GitHub Release](https://github.com/raphabot/pipefort/releases). See the
[installation docs](https://pipefort.com/docs/cli/installation) for details.

Check what you installed with `pipefort --version` (or `pipefort version`).

**Requirements:** none for a local scan — the released binary is self-contained.
Go 1.25+ only to build from source; `git` on `PATH` only for `--git`; `gh` / `glab`
optionally, to discover a token.

### Docker

The image built from `Dockerfile.action` exists to back the GitHub Action, so its
`ENTRYPOINT` is the action wrapper, which builds its arguments from `INPUT_*`
environment variables and **ignores anything passed on the command line**. Use one
of these two forms:

```bash
docker build -f Dockerfile.action -t pipefort .

# (a) bypass the wrapper and drive the CLI directly
docker run --rm -v "$PWD:/repo" --entrypoint pipefort pipefort -p /repo

# (b) drive the wrapper through its inputs, exactly as the Action does
docker run --rm -v "$PWD:/repo" -e INPUT_PATH=/repo -e INPUT_OUTPUT=console pipefort
```

See [examples/docker/](./examples/docker/) for the details.

## Quick start

```bash
# Scan the current directory
pipefort -p .

# Scan a remote repository (GitHub owner/repo, or a full GitHub/GitLab URL)
pipefort -g owner/repo
pipefort -g https://gitlab.com/group/subgroup/project

# JSON output (machine-readable)
pipefort -p . -o json

# SARIF 2.1.0 for GitHub code scanning
pipefort -p . -o sarif > pipefort.sarif

# Auto-fix fixable findings in workflow YAML, in place
pipefort -p . --fix
```

No configuration, token, or network access is required for a local scan. Findings
are printed grouped by file, followed by a severity summary and any toxic
combinations:

```text
--- CI/CD SECURITY SCAN RESULTS ---

File: .github/workflows/ci.yml
  Line 26:14 [HIGH] (CICD-SEC-4) Poisoned Pipeline Execution (Shell Injection)
    Description: Step "Print PR Title" in job "build" contains inline script shell injection risk. ...
    Remediation: Assign the untrusted context variable to an environment variable in the step ...

-----------------------------------
✖ Scan Summary: 4 High, 4 Medium, 0 Low, 0 Info findings.


--- ATTACKER MIND — TOXIC COMBINATIONS ---
[CRITICAL] Poisoned Exfiltration — injection harvests in-scope secrets (.github/workflows/ci.yml)
  Chain:  Command injection → Reachable hardcoded secret → Broad token amplifies blast radius → Secret exfiltration
```

**Exit codes:** `0` when nothing reached the `--fail-on` threshold; `1` when
something did — or when the scan itself failed. The two are not distinguishable by
exit code alone; parse `-o json` if you need to tell them apart.

### Optional production configuration

Everything above works unconfigured. Add these deliberately:

- **`.pipefort.yml`** — per-rule disables, severity overrides, file/line ignores, and
  an action allow/deny policy. Annotated sample:
  [examples/config/pipefort.yml](./examples/config/pipefort.yml).
- **`# pipefort: ignore[rule-id]`** — suppress a single finding inline:
  [examples/config/inline-ignores.yml](./examples/config/inline-ignores.yml).
- **`$GITHUB_TOKEN`** — enables the online supply-chain pin audits and lifts GitHub's
  60-requests/hour anonymous limit.
- **`--fail-on HIGH`** — loosen the CI gate while burning down MEDIUM findings.
- **`-o sarif` + `upload-sarif`** — findings land in the GitHub Security tab.

Useful flags (run `pipefort --help` for the full list, or see the
[flags reference](https://pipefort.com/docs/cli/flags)):

| Flag | Purpose |
|------|---------|
| `-p, --path` | Local path to scan (default `.`). |
| `-f, --file` | Scan a single workflow file. |
| `-g, --git` | Remote repo: `owner/repo`, or a full GitHub/GitLab URL. |
| `--org` | Scan every repo owned by a GitHub org or user (needs a token). |
| `-o, --output` | `console` (default), `json`, or `sarif`. |
| `-s, --fail-on` | Exit 1 on findings at/above `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `NONE` (default `MEDIUM`). |
| `-r, --ruleset` | `all` (default), `owasp`, `slsa`, or a specific SLSA level. |
| `--min-confidence` | Drop findings below `HIGH`, `MEDIUM`, or `LOW`. |
| `--persona` | Noise tier: `regular` (default), `pedantic`, or `auditor`. |
| `--fix` | Auto-fix fixable workflow findings in place (local scans only). |
| `--fix-settings` | Apply fixable GitHub repo-config findings via the API (needs `--git` at GitHub + `administration:write`). |
| `--fix-settings-gl` | Apply fixable GitLab project-settings findings (needs `--git` at GitLab + `--gitlab-token`). |
| `--fix-mr` | Open a GitLab MR per fixable workflow finding (needs `--gitlab-token` with `api` scope). |
| `--dry-run` | Preview mutations without writing. Applies to `--fix-settings` and `--fix-mr` — **not** to `--fix`. |
| `--audit-pins` / `--offline` | Force online supply-chain pin audits on / off. |
| `--github-token` / `--gitlab-token` | Tokens for remote scans, settings audits, and remote fixes. |
| `--gitlab-host` | GitLab host for project-settings audits on a local `--path`/`--file` scan (default `gitlab.com`). |
| `--keep-temp` | Keep the temporary clone directory created by `--git`. |
| `--config` / `--no-config` | Use / ignore a `.pipefort.yml` config file. |

Online supply-chain pin audits (impostor-commit, known-vulnerable, typosquat,
etc.) run automatically when a GitHub token is available (`--github-token`,
`$GITHUB_TOKEN`/`$GH_TOKEN`, or `gh auth token`). Use `--audit-pins` to force
them on without a token, or `--offline` to keep the scan fully local.

## GitHub Action

Run Pipefort in CI and upload results to GitHub code scanning:

```yaml
name: Pipefort
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  pipefort:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: scan
        uses: raphabot/pipefort@v0.1.7   # pin a released tag; see latest at /releases
        with:
          path: .
          ruleset: all
          fail-on: MEDIUM
          output: sarif        # default; writes pipefort.sarif

      - name: Upload SARIF
        if: always()           # upload findings even when the scan fails the build
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

Action inputs: `path`, `ruleset`, `fail-on`, `output`, `sarif-file`, and
`github-token` (defaults to the workflow token, enabling the online pin audits;
set it to `''` to keep the scan offline). See the
[CI integration docs](https://pipefort.com/docs/cli/ci-integration).

## MCP server

Pipefort ships a [Model Context Protocol](https://modelcontextprotocol.io)
server so AI coding assistants can scan CI workflows **as they write them** —
catching an injection sink or an unpinned action before it is committed:

```bash
# Register with Claude Code
claude mcp add pipefort -- pipefort mcp
```

`pipefort mcp` serves the scanner over stdio (read-only, offline). See the
[MCP docs](https://pipefort.com/docs/cli/mcp).

## When to use Pipefort (and when not to)

**Use it when** the risk lives in the *pipeline*: poisoned pipeline execution,
unpinned or impostor actions, `pull_request_target` misuse, shell injection from
`github.event.*`, over-broad `GITHUB_TOKEN` permissions, secrets hardcoded in
workflow YAML, missing branch protection, or SLSA build-track gaps — on GitHub
Actions **and** GitLab CI.

**Use something else when** you need application-source SAST (CodeQL, Semgrep),
dependency CVE scanning (Dependabot, Trivy, Grype), secrets in git history
(gitleaks, trufflehog), or container/runtime security. Pipefort complements those;
it does not replace them. If you only use GitHub Actions and want the narrowest
established tool, [zizmor](https://github.com/zizmorcore/zizmor) is the closest
alternative — it has no GitLab, repository-settings, or online pin-integrity
coverage.

See [AGENTS.md](./AGENTS.md#when-to-use-pipefort-and-when-not-to) for the full
comparison.

## Documentation

Full documentation, including the complete rules reference, lives at
**[pipefort.com/docs](https://pipefort.com/docs)**. The hosted web dashboard
(scan history, trends, org-wide posture) is at
**[pipefort.com](https://pipefort.com)**.

In this repository:

- **[AGENTS.md](./AGENTS.md)** — the complete integration guide (install, CLI and
  Go library reference, configuration schema, error table, stability guarantees).
  Written for AI coding assistants; useful to humans too.
- **[llms.txt](./llms.txt)** — machine-readable index of the documentation.
- **[examples/](./examples/)** — runnable recipes for CI, GitLab, config, MCP, and Docker.

Go API reference:
[pkg.go.dev/github.com/raphabot/pipefort](https://pkg.go.dev/github.com/raphabot/pipefort).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). Every
feature (especially a new scanner rule) ships with tests.

## Security

To report a vulnerability, see [SECURITY.md](./SECURITY.md). Please use GitHub's
private vulnerability reporting rather than a public issue.

## License

[Apache License 2.0](./LICENSE) © 2026 Raphael Bottino.
