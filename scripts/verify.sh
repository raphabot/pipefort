#!/usr/bin/env bash
# The single "is it green?" target: the same checks as .github/workflows/ci.yml.
# Agents loop on this until it passes. Humans run it before opening a PR.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  printf '%s\n' "$unformatted"
  echo "Run: gofmt -w <files above>"
  exit 1
fi

step "go build"
go build ./...

step "go vet"
go vet ./...

step "go test"
go test ./...

step "no-pgx guard (engineering/adr/0002)"
if go list -deps . | grep jackc/pgx; then
  echo "ERROR: the CLI transitively depends on jackc/pgx."
  exit 1
fi

printf '\nverify: all green\n'
