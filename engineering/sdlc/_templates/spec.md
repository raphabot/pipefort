# Spec: <short title>

- **Intent:** [intent.md](./intent.md) · **Date:** YYYY-MM-DD
- **Risk:** low | medium | high. High means a new network call, a fixer that
  rewrites user files, or a change to a public `pkg/scanner` API

## Requirements
Numbered, testable statements. Each one maps to at least one table-driven test case.

1. …

## Detection design
- Rule id, category, severity, surface, platform, frameworks (catalog entry).
- True positives: the exact YAML shapes that must fire.
- **True negatives**: the legitimate look-alikes that must NOT fire. This is
  the false-positive budget.
- Auto-fix: is it fixable? What does the rewrite look like, and is it idempotent?

## Policy check
- Plain local scan stays offline. Any network use is opt-in and token-gated.
- No telemetry. No dependency that reaches a datastore (no pgx).
- Public API changes (`pkg/scanner` exports, CLI flags, JSON/SARIF shape) need
  AGENTS.md + llms.txt updates.

## Companion cloud PR
Docs page `docs/rules/<id>.mdx`, overview + `docs.json` entry, SPA wiring.

## Out of scope
