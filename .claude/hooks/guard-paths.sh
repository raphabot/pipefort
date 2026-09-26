#!/usr/bin/env bash
# PreToolUse guard for file edits (Edit/MultiEdit/Write/NotebookEdit).
#
# Deterministic build-phase guardrails. They run on every edit, for every
# session, without relying on the model remembering CLAUDE.md:
#   - .env files                                  -> deny
#   - release, CI and the published Action        -> ask a human
#   - existing tests and testdata while
#     protect-tests is on                         -> deny (fix code, not tests)
set -uo pipefail

input=$(cat)
file=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' <<<"$input")
[ -z "$file" ] && exit 0

root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
rel="${file#"$root"/}"

decide() {
  jq -n --arg d "$1" --arg r "$2" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:$d,permissionDecisionReason:$r}}'
  exit 0
}

case "$rel" in
  *.env.example) ;;
  .env|.env.*|*/.env|*/.env.*)
    decide deny "$rel may hold real secrets and is off-limits to agents." ;;
  .github/workflows/*|.goreleaser.yaml|action.yml|action/*|Dockerfile.action)
    decide ask "$rel controls CI, releases or the published GitHub Action that users run. Confirm this edit is intended." ;;
esac

if [ -e "$root/.claude/state/protect-tests" ]; then
  case "$rel" in
    *_test.go|testdata/*|*/testdata/*)
      [ -e "$file" ] && decide deny "Test protection is on (.claude/state/protect-tests): fix the code under test, not $rel. If the test or fixture itself is wrong, stop and explain why to the user."
      ;;
  esac
fi
exit 0
