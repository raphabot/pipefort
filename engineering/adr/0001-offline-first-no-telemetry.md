# 0001 — The CLI is offline-first and never phones home

**Status:** Accepted (recorded retroactively, 2026-09)

## Context
The users are security teams scanning pipelines that often sit in sensitive or
air-gapped environments. A scanner that makes surprise network calls is itself
a supply-chain risk.

## Decision
A plain local scan (`pipefort -p <dir>`) makes no network calls. Online audits
(`--audit-pins`) and remote scans (`--git`, `--org`) are opt-in and token-gated.
There is no telemetry, analytics or update check.

## Consequences
- Any new network use must sit behind an explicit flag and be documented in
  AGENTS.md.
- Reviews treat a new `net/http` import on the default path as a Blocker.
