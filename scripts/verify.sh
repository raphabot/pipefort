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

step "go test (includes the golden corpus, testdata/corpus)"
go test ./...

step "no-pgx guard (engineering/adr/0002)"
if go list -deps . | grep jackc/pgx; then
  echo "ERROR: the CLI transitively depends on jackc/pgx."
  exit 1
fi

step "golangci-lint (new issues vs origin/main, if installed)"
if command -v golangci-lint >/dev/null 2>&1; then
  base=origin/main
  git rev-parse --verify --quiet "$base" >/dev/null || base=main
  golangci-lint run --new-from-rev="$base" ./...
else
  echo "skipped: golangci-lint not installed (CI runs it; brew install golangci-lint)"
fi

printf '\nverify: all green\n'
