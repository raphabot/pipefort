# Pipefort

**Scan your CI/CD pipelines for the OWASP Top 10 CI/CD security risks.** Pipefort
is a fast, offline-first CLI that inspects GitHub Actions and GitLab CI pipelines
— 60+ rules spanning workflow YAML, online action-pin supply-chain audits, SLSA
build-track coverage, and repository/project configuration — with auto-fix and
cross-finding "Attacker Mind" toxic-combination detection.

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

### Docker

Build the CLI image from source and run it against a mounted repo:

```bash
docker build -f Dockerfile.action -t pipefort .
docker run --rm -v "$PWD:/repo" pipefort -p /repo
```

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
| `--fix` | Auto-fix fixable workflow findings in place. |
| `--audit-pins` / `--offline` | Force online supply-chain pin audits on / off. |
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
        uses: raphabot/pipefort@v0.1.0   # pin a released tag; see latest at /releases
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

## Documentation

Full documentation, including the complete rules reference, lives at
**[pipefort.com/docs](https://pipefort.com/docs)**. The hosted web dashboard
(scan history, trends, org-wide posture) is at
**[pipefort.com](https://pipefort.com)**.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). Every
feature (especially a new scanner rule) ships with tests.

## Security

To report a vulnerability, see [SECURITY.md](./SECURITY.md). Please use GitHub's
private vulnerability reporting rather than a public issue.

## License

[Apache License 2.0](./LICENSE) © 2026 Raphael Bottino.
