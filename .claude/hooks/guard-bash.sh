#!/usr/bin/env bash
# PreToolUse guard for Bash. It is the approval gate for releases and shared
# history: agents may build and test freely, but tagging, releasing or
# rewriting main needs a human. Merges to main auto-tag via release-cli.yml.
set -uo pipefail

cmd=$(jq -r '.tool_input.command // empty')
[ -z "$cmd" ] && exit 0

decide() {
  jq -n --arg d "$1" --arg r "$2" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:$d,permissionDecisionReason:$r}}'
  exit 0
}

if grep -Eq 'git[[:space:]]+push' <<<"$cmd"; then
  if grep -Eq '(--force|[[:space:]]-f([[:space:]]|$)|--force-with-lease)' <<<"$cmd" &&
     grep -Eq '(^|[[:space:]:/])(main|master)([[:space:]]|$)' <<<"$cmd"; then
    decide deny "Force-pushing main is never allowed."
  fi
  if grep -Eq '[[:space:]](origin[[:space:]]+)?(HEAD:)?(main|master)([[:space:]]|$)' <<<"$cmd"; then
    decide deny "main only changes through a reviewed PR. Push a branch and open a PR instead."
  fi
  if grep -Eq '(--tags|[[:space:]]v[0-9]+\.[0-9]+)' <<<"$cmd"; then
    decide ask "Pushing a version tag publishes a release (GoReleaser, Homebrew). release-cli.yml normally tags on merge. Approve only deliberately."
  fi
fi
if grep -Eq 'git[[:space:]]+tag[[:space:]]+(-[a-z]+[[:space:]]+)*v[0-9]' <<<"$cmd"; then
  decide ask "Creating a version tag. Releases are normally auto-tagged by release-cli.yml on merge."
fi
if grep -Eq '(goreleaser[[:space:]]+release|gh[[:space:]]+release[[:space:]]+(create|upload|edit|delete))' <<<"$cmd"; then
  decide ask "This publishes or changes a public release. A human must approve it."
fi
exit 0
