# Contributing to Pipefort

Thanks for your interest in improving Pipefort! This repository is the
open-source CLI and scan engine. Contributions — new rules, fixes, bug reports,
and docs — are welcome.

## Prerequisites

- Go 1.25 or newer (see `go.mod`).

## Build and test

```bash
go build ./...
go vet ./...
go test ./...
```

Run the CLI locally against the bundled fixtures:

```bash
go run . -p testdata/
go run . -p testdata/ -o json
```

## Every feature ships with tests

A change is not done until `go test ./...` is green. New behavior needs new
tests:

- **Scanner rules** get table-driven tests in `pkg/scanner` (see the existing
  `*_test.go` files for the pattern).
- **VCS / remote operations** use the httptest-based mocks in `pkg/vcs`.

## Adding a scanner rule

All detection lives in `pkg/scanner`. To add a rule:

1. Implement a `Check*` function that returns `Finding` structs.
2. Register it in `catalog.go` (ID, category, severity, confidence, surface,
   platform) and wire it into the scan path (`ScanBytes`/`ScanDir` or the
   settings/online audit path as appropriate).
3. If the finding is auto-fixable, add support in `fixer.go` (and the GitLab
   fixer where relevant).
4. Wire any new CLI flag/output into `main.go`, and expose it through
   `pkg/mcp` if it belongs in the MCP surface.
5. Add tests.

**Cross-repo docs flow.** User-facing docs live in the separate **private
`pipefort-cloud` repo** (Mintlify), not here. A new rule therefore needs a
companion PR there that adds a `docs/rules/<id>.mdx` page and an entry in
`docs/rules/overview.mdx`. Call this out in your PR description so a maintainer
can land the docs alongside the engine change and the tag/pin bump.

## Code style

- Run `gofmt` — `gofmt -l .` must report no files.
- `go vet ./...` must be clean.
- Keep the CLI offline-first: no telemetry, and no dependency that reaches a
  datastore. (CI enforces a no-pgx dependency guard.)

## Pull requests

- Keep PRs focused; one logical change per PR.
- Describe what changed and why; link any related issue.
- Make sure CI is green (build, vet, gofmt, tests, and the dependency guard).

## Sign-off (optional)

A [Developer Certificate of Origin](https://developercertificate.org/) sign-off
is welcome but not required. Add one with `git commit -s` if you'd like to
certify your contribution.

## Reporting security issues

Please do **not** open public issues for vulnerabilities. See
[SECURITY.md](./SECURITY.md).
