#!/bin/sh
# Entrypoint for the Pipefort GitHub Action. Assembles CLI flags from the
# action inputs (exposed by GitHub as INPUT_<NAME>, uppercased, dashes→
# underscores) and runs the scanner.
#
# In SARIF mode we always write the report file and emit the `sarif-file` step
# output *before* propagating pipefort's exit code, so a later
# `github/codeql-action/upload-sarif` step (guarded with `if: always()`) can
# still upload findings even when the scan fails the build.
set -e

PATH_ARG="${INPUT_PATH:-.}"
RULESET="${INPUT_RULESET:-all}"
FAIL_ON="${INPUT_FAIL_ON:-MEDIUM}"
OUTPUT="${INPUT_OUTPUT:-sarif}"
SARIF_FILE="${INPUT_SARIF_FILE:-pipefort.sarif}"

# Expose the token (workflow token by default) as GITHUB_TOKEN so the online
# supply-chain pin audits auto-enable. An empty input keeps the scan offline.
if [ -n "$INPUT_GITHUB_TOKEN" ]; then
  export GITHUB_TOKEN="$INPUT_GITHUB_TOKEN"
fi

set -- -p "$PATH_ARG" -r "$RULESET" -s "$FAIL_ON" -o "$OUTPUT"

if [ "$OUTPUT" = "sarif" ]; then
  set +e
  pipefort "$@" > "$SARIF_FILE"
  code=$?
  set -e
  if [ -n "$GITHUB_OUTPUT" ]; then
    echo "sarif-file=$SARIF_FILE" >> "$GITHUB_OUTPUT"
  fi
  exit "$code"
fi

exec pipefort "$@"
