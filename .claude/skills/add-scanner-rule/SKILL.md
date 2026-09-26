---
name: add-scanner-rule
description: Use when adding a new detection rule, a toxic combination, or an auto-fix to the pipefort scan engine (pkg/scanner), or when changing an existing rule's behavior.
---

# Adding a scanner rule

Follow the shape of a recent rule PR, e.g. `git show --stat 6904c9a` (YAML
hardening) or `4a9e950` (artifact retention, which includes a fixer).

## 1. Spec first
Use the `sdlc-artifacts` skill. It must list the **true positives** and the
**true negatives** (legitimate look-alikes). The negatives become test cases.

## 2. Implement (engine, this repo)
- **ID constant** in `pkg/scanner/catalog.go` (`RuleXxx RuleID = "cicd-sec-N-…"`).
- **Catalog entry** in `ruleCatalog()`: Category, Title, DefaultSeverity,
  Surface, Platform, a Description that states *each* finding and its severity,
  `DocURL: "/rules/<id>"`, Frameworks, and Persona if it isn't regular.
- **Check** in its own file `pkg/scanner/<topic>.go`. Decide on the parsed
  document, not on text patterns. Emit `Finding`s with `RuleID` set
  (`TestEveryFindingHasARuleID` enforces this).
- **Wire** it into `scanner.go` (`ScanBytes` or the per-platform dispatch).
- **Auto-fix**, if fixable: `pkg/scanner/fixer.go`, and `pkg/vcs/workflow_fixer.go`
  for remote fixes. Fixes must be idempotent: running `--fix` twice changes nothing.
- **Tests**: table-driven in `pkg/scanner/<topic>_test.go`, with positives,
  negatives (the look-alikes), GitHub **and** GitLab where the platform is
  `PlatformAny`, and a fixer round-trip test.
- **Offline-first** (ADR 0001): no network on the default path.

## 3. Sync the consumer docs in this repo
If the rule count, a CLI flag, an output field or an exported symbol changed,
update `AGENTS.md`, `llms.txt` and `README.md`. Avoid hardcoding counts where
you can.

## 4. Verify
```bash
scripts/verify.sh
go run . -p testdata/   # sanity-check the output on the fixtures
```

## 5. Companion cloud PR (ADR 0003)
After merge, `release-cli.yml` auto-tags. In `pipefort-cloud`, follow its
`engine-pin-bump` skill: pin bump, `docs/rules/<id>.mdx`, the overview and
`docs.json` entries, and SPA wiring. Mention that PR in this one.
