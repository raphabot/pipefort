# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

Pipefort scans CI/CD pipelines (GitHub Actions and GitLab CI) for the OWASP
Top 10 CI/CD security risks. This repository is the **open-source CLI and scan
engine**.

- **CLI** (`main.go`, module binary `pipefort`) — scans a local path or a remote
  repo; supports auto-`--fix`, JSON/SARIF output, org-wide scans, and a
  `pipefort mcp` Model Context Protocol server.
- **Engine** (`pkg/scanner`) — all detection lives here; `pkg/reporter` renders
  it, `pkg/mcp` exposes it over MCP, and `pkg/vcs` holds token-parameterized VCS
  operations (remote fetch, org scan, workflow/settings fixers).

> **The web app, Go API, Supabase, and the Mintlify docs site live in the
> separate private `pipefort-cloud` repo.** That repo depends on this module
> (`github.com/raphabot/pipefort`) as an external dependency. A new scanner rule
> is a PR **here** (rule + fix + CLI wiring + a rules doc), plus a companion
> private-repo PR (SPA wiring + `docs/rules/*` pages). See conventions below.

## Commands

- Go: `go build ./...` · `go vet ./...` · `go test ./...`
  - single package/test: `go test ./pkg/scanner/ -run TestFilterFindings -v`
- CLI: `go run . -p <dir>` · `go run . -g owner/repo -o json` · `-r owasp`
  (ruleset) · `--fix`
- MCP server: `go run . mcp` (stdio)
- Format/vet before shipping: `gofmt -l .` (must be empty) · `go vet ./...`

**No-pgx guard.** The CLI must never pull in the Postgres driver. Verify with:

```bash
go list -deps . | grep jackc/pgx    # must print nothing
```

## Architecture (the parts that span multiple files)

**One scan engine, one CLI over it.** All detection lives in `pkg/scanner` (the
catalog in `catalog.go` registers 60+ rules across GitHub Actions + GitLab CI,
online supply-chain audits, SLSA, and repo-settings; each `Check*` produces
`Finding` structs; `FilterFindings` applies the `all`/`owasp`/`slsa` ruleset;
`fixer.go` rewrites YAML for the fixable categories). Never put scan logic in the
CLI layer. Two entrypoints exist for a reason: `ScanFile`/`ScanDir` read from
disk, while **`ScanBytes(name, content)` scans in memory** — used by `pkg/vcs`
(and the private web API) to scan workflow files fetched over the GitHub/GitLab
API **without cloning** (`ScanFile` is just `ScanBytes` after `os.ReadFile`).

**Package layering.** `pkg/scanner` is a leaf. `pkg/reporter` and `pkg/mcp`
depend only on it. `pkg/vcs` provides remote-fetch, org-scan, and remote-fix
operations parameterized by a token — no auth-minting, no database. `main.go`
wires them together. Keep this layering: the CLI must not gain any dependency
that reaches a datastore or SaaS concern.

## Conventions (read before adding a feature)

1. **Every new feature ships with tests.** A feature is not done until
   `go test ./...` is green. Scanner rules get table-driven tests in
   `pkg/scanner`; VCS operations use the httptest-based mocks in `pkg/vcs`.

2. **A new scanner rule is a cross-repo change.** The rule, its auto-fix (when
   fixable), and CLI wiring land as a PR **here**, together with a
   `docs/rules/<id>.mdx` page... *except* the docs site itself lives in the
   private `pipefort-cloud` repo. So in practice a new rule is:
   - **This repo:** the `Check*` implementation + catalog registration in
     `pkg/scanner`, any `fixer.go` support, CLI/MCP wiring, and tests.
   - **Private `pipefort-cloud` repo:** SPA wiring, plus the
     `docs/rules/<id>.mdx` page and its entry in `docs/rules/overview.mdx`.
   The private repo picks up the new rule after this module is tagged and its
   `go.mod` pin is bumped.

3. **Keep the CLI self-contained and offline-first.** Online audits
   (`--audit-pins`) and remote scans (`--git`, `--org`) are opt-in and
   token-gated; a plain local scan makes no network calls. Do not add telemetry
   or phone-home behavior.

4. **Use the appropriate skills instead of hand-rolling.** `security-review` on
   security-sensitive changes; `code-review` before shipping.
