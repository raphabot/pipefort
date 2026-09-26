# 0002 — Leaf scanner package; no datastore dependency in the CLI

**Status:** Accepted (recorded retroactively, 2026-09)

## Context
The private SaaS consumes this module. Without a hard boundary, SaaS concerns
(Postgres, auth minting) would leak into the open-source CLI.

## Decision
`pkg/scanner` is a leaf. `pkg/reporter` and `pkg/mcp` depend only on it.
`pkg/vcs` is token-parameterized, with no auth minting and no database.
`main.go` wires them together. The CLI must never pull in `jackc/pgx`.

## Consequences
- CI fails if `go list -deps . | grep jackc/pgx` matches. `scripts/verify.sh`
  runs the same check.
- `ScanBytes` exists so callers can scan in memory without cloning. Keep it
  the canonical entrypoint (`ScanFile` is a thin wrapper).
