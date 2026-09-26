# SDLC artifacts

Every non-trivial change leaves a paper trail in git. It goes in a dated
folder here and merges with the PR that implements it:

```
engineering/sdlc/2026-10-01-unsafe-yaml-tags/
  intent.md   why: problem, outcome, constraints    (human-owned)
  spec.md     what: requirements + design + policy   (reviewed before build)
  plan.md     how: steps, tests, verification        (updated on deviation)
```

| Change size | Needs |
|---|---|
| Typo, dependency bump, one-line fix | nothing |
| Bug fix or small enhancement | `plan.md` |
| New rule, fixer, CLI flag, output-format or public API change | all three |

Templates live in [`_templates/`](./_templates). The `sdlc-artifacts` skill
(`.claude/skills/sdlc-artifacts`) walks through producing them. Cross-cutting
decisions that outlive one change go in [`../adr/`](../adr).

**Source of truth:** the files in the repo. A GitHub issue links to the folder,
and the folder links back to the issue.
