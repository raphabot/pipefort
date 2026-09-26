# Review policy

This is the policy every PR is reviewed against, whether the reviewer is a
human, the in-session `/code-review`, or the Claude GitHub Action. Reviewers
rank findings by severity. Humans spend their attention on intent and risk.

## Severity
- **Blocker**: a network call on the default scan path, telemetry, a `pgx` (or
  any datastore) dependency, a fixer that can corrupt or silently change the
  meaning of a user's workflow, a panic on malformed YAML, or a breaking change
  to a public `pkg/scanner` API or the JSON/SARIF shape without a version note.
- **Major**: false positives on common legitimate patterns, a missing
  true-negative test, a missing GitLab case for a `PlatformAny` rule, a
  non-idempotent fix, a catalog entry that doesn't match the emitted findings,
  or AGENTS.md / llms.txt out of sync with a changed CLI or API surface.
- **Minor**: maintainability issues that will plausibly cause a bug later.
- **Nit**: style or naming. **At most 3 per review.** Skip anything gofmt or vet
  already enforces.

## Always check
1. **Offline-first** (ADR 0001) and **layering / no-pgx** (ADR 0002).
2. **Detection quality**: positives *and* look-alike negatives are tested.
   Decisions are made on the parsed document, not by regex over text.
3. **Findings**: `RuleID` set, severity matches the catalog Description, and
   `DocURL` points at a page the companion cloud PR creates (ADR 0003).
4. **Fixers**: idempotent, minimal diff, comments and formatting preserved,
   round-trip tested.
5. **Untrusted input**: every workflow file is attacker-controlled. Watch for
   unbounded recursion or expansion and huge allocations.
6. **Workflows and the Action**: third-party actions are pinned to a commit
   SHA, with minimal `permissions:`.
7. **Artifacts**: non-trivial changes link `engineering/sdlc/<folder>/`, and the
   diff matches `plan.md` or the plan's Deviations explain the difference.

## Out of scope
`go.sum`, `testdata/` fixture contents (unless they are the point of the PR),
and prose style in `README.md`.

## Feedback loop
When a review finds a class of mistake twice, add it to "Common mistakes" in
CLAUDE.md, or turn it into a hook, skill or test so it cannot recur.
