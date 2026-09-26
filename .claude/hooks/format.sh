#!/usr/bin/env bash
# PostToolUse: keep Go files gofmt-clean as they are written, so CI's gofmt
# check never fails on agent output.
set -uo pipefail
file=$(jq -r '.tool_input.file_path // empty')
case "$file" in
  *.go) [ -f "$file" ] && gofmt -w "$file" ;;
esac
exit 0
