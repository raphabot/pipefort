# Intent: <short title>

- **Author:** <name> · **Date:** YYYY-MM-DD · **Issue:** #<n> (or "none")
- **Status:** proposed | accepted | rejected (reason)

## Problem
What is wrong or missing today, and for whom? Evidence: a user report, a
metric, an incident, a competitor gap. Link it.

## Desired outcome
What is true once this ships? Say it as observable behavior, not as a solution.

## Affected systems
Scanner rules (`pkg/scanner`)? Fixer (`fixer.go`, `pkg/vcs`)? CLI flags (`main.go`)?
MCP (`pkg/mcp`)? Reporters and SARIF? AGENTS.md / llms.txt? Companion `pipefort-cloud` PR?

## Constraints
Offline-first (no network on a plain local scan), no telemetry, no pgx, false-positive budget.

## Success signal
How we will know it worked: a test, a metric, a user-visible check.

## Open questions
