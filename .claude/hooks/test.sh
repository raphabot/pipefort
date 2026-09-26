#!/usr/bin/env bash
# Deterministic tests for the guard hooks: feed synthetic tool inputs, assert
# the decision. Runs in scripts/verify.sh and CI, so a hook edit can't silently
# open a hole. Add a case whenever a hook changes.
set -uo pipefail
cd "$(dirname "$0")/../.."
export CLAUDE_PROJECT_DIR="$PWD"
fails=0

expect() { # expect <allow|ask|deny> <hook> <json-key> <value>
  local want=$1 hook=$2 key=$3 val=$4 out got
  out=$(jq -n --arg k "$key" --arg v "$val" '{tool_input:{($k):$v}}' | ".claude/hooks/$hook")
  got=$( [ -z "$out" ] && echo allow || jq -r .hookSpecificOutput.permissionDecision <<<"$out")
  if [ "$got" != "$want" ]; then echo "FAIL $hook: $val -> $got (want $want)"; fails=$((fails+1)); fi
}
P=guard-paths.sh; B=guard-bash.sh; F=file_path; C=command

expect deny  $P $F "$PWD/.env"
expect allow $P $F "$PWD/.env.example"
expect ask   $P $F "$PWD/.github/workflows/ci.yml"
expect ask   $P $F "$PWD/.goreleaser.yaml"
expect ask   $P $F "$PWD/action.yml"
expect ask   $P $F "$PWD/Dockerfile.action"
expect allow $P $F "$PWD/pkg/scanner/scanner.go"
expect allow $P $F "$PWD/pkg/scanner/catalog_test.go"

mkdir -p .claude/state; had_switch=0; [ -e .claude/state/protect-tests ] && had_switch=1
touch .claude/state/protect-tests
expect deny  $P $F "$PWD/pkg/scanner/catalog_test.go"
expect deny  $P $F "$PWD/testdata/secure-workflow.yml"
expect allow $P $F "$PWD/pkg/scanner/brand_new_test.go"
[ $had_switch = 1 ] || rm -f .claude/state/protect-tests

expect deny  $B $C "git push origin main"
expect deny  $B $C "git push --force origin main"
expect allow $B $C "git push -u origin feat/x"
expect ask   $B $C "git tag v0.2.0"
expect ask   $B $C "git push origin v0.2.0"
expect ask   $B $C "git push --tags"
expect ask   $B $C "gh release create v0.2.0"
expect ask   $B $C "goreleaser release --clean"
expect allow $B $C "go test ./..."

# Bare `git push` pushes the current branch: deny on main, allow elsewhere.
tmp=$(mktemp -d); git -C "$tmp" init -q -b main
push_in() { local o; o=$(jq -n --arg c "$1" --arg d "$tmp" '{tool_input:{command:$c},cwd:$d}' | .claude/hooks/guard-bash.sh); [ -z "$o" ] && echo allow || jq -r .hookSpecificOutput.permissionDecision <<<"$o"; }
[ "$(push_in 'git push')" = deny ] || { echo "FAIL bare git push on main not denied"; fails=$((fails+1)); }
git -C "$tmp" switch -q -c feat/x
[ "$(push_in 'git push')" = allow ] || { echo "FAIL bare git push on feature branch denied"; fails=$((fails+1)); }
rm -rf "$tmp"

[ $fails -eq 0 ] && echo "hook tests: all passed" || { echo "hook tests: $fails failed"; exit 1; }
