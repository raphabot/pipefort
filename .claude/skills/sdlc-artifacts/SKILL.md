---
name: sdlc-artifacts
description: Use when starting a new scanner rule, fixer, CLI flag, output-format or public API change, or a non-trivial bug fix in the pipefort engine, before writing code. Produces the committed intent.md, spec.md and plan.md under engineering/sdlc/.
---

# SDLC artifacts: intent, then spec, then plan

These files are the audit trail for why a change exists and what was agreed.
They merge **with** the PR. This repo is public, so write them for outside
readers too, and keep customer names and private data out.

1. **Size it** using `engineering/sdlc/README.md`. A bug fix needs `plan.md`.
   A rule, fixer, flag or API change needs all three.
2. **Create** `engineering/sdlc/<YYYY-MM-DD>-<kebab-slug>/` from `_templates/`.
3. **intent.md**: brainstorm with the user, one question at a time. Cover the
   problem, the evidence (a real-world workflow, a CVE, an incident) and the
   outcome. The user accepts it before you design anything.
4. **spec.md**: apply `engineering/adr/*`. For a rule, the true-negative list
   (legitimate look-alikes that must not fire) is mandatory, because false
   positives are how scanners lose users. Mark Risk: high for new network calls,
   rewriting fixers, or public API changes, and ask the user for explicit
   sign-off on those.
5. **plan.md** (in plan mode): small steps, each leaving `scripts/verify.sh`
   green, with every requirement mapped to a test case. For a rule, follow
   the `add-scanner-rule` skill.
6. **While building**: record departures from the plan under `## Deviations`
   in the same commit, and link the folder from the PR description.
   Superpowers' brainstorming and plan skills write here, not to
   `docs/superpowers/`.
