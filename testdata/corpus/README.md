# Golden corpus (the scanner's eval set)

Every `*.yml` file in this directory is a realistic pipeline that
`pkg/scanner/corpus_test.go` (`TestCorpus`) scans **offline** through the public
`scanner.ScanBytes` API. A sorted, stable projection of the findings (rule id,
severity, confidence, line, column) is compared to `<case>.golden.json`. Free
text (titles, descriptions) is left out on purpose so rewording a message does
not churn the corpus. The test also swaps out `http.DefaultTransport` and fails
if a scan makes a network request, because the default scan path must stay
offline (ADR 0001).

## The rule: every reported false positive or false negative becomes a case

When a user (or a review, or you) finds a false positive or a missed
detection, add the smallest realistic pipeline that reproduces it here, **before
or together with the fix**. It stays here permanently, so the regression can't
come back unnoticed. The same applies to every new rule. It gets at least one
positive case and one look-alike (a legitimate pipeline that must not trigger
it). See `.claude/skills/add-scanner-rule/SKILL.md`.

## Case layout

| File name | Scanned as | Platform |
| --- | --- | --- |
| `<case>.yml` | `.github/workflows/<case>.yml` | GitHub Actions |
| `<case>.gitlab-ci.yml` | `.gitlab-ci/<case>.yml` | GitLab CI |

`ScanBytes` dispatches on the path, which is why the test rewrites the name.
Prefixes are only a convention: `gh-` / `gl-` for hand-written cases,
`fixture-` for copies of the long-standing `testdata/*.yml` fixtures, and
`example-` for copies of our own `examples/`.

Each case starts with a comment header:

```yaml
# corpus: positive | lookalike | fixture
# models: what real-world attack (or legitimate look-alike) this is
# expect: <rule-id>        # asserted: at least one finding with this rule
# expect-none: <rule-id>   # asserted: no finding with this rule
# known-gap (...): ...     # NOT asserted: current behavior is wrong, see below
```

The `expect` / `expect-none` directives state the intent. They are checked
independently of the golden, so `-update` cannot silently bless a lost
detection or a new false positive on a look-alike. The golden records
*everything* else, including low-severity best-practice findings.

Write cases yourself. Don't copy third-party workflow files verbatim. Action
SHAs in the cases look real but are not verified (the test is offline), so
don't copy them into real workflows.

## Adding a case

1. Write `testdata/corpus/<case>.yml` (or `.gitlab-ci.yml`) with the header above.
2. Generate its golden:
   ```bash
   go test ./pkg/scanner/ -run TestCorpus -update
   ```
   Run `-update` against `./pkg/scanner/` only, because other packages don't
   define the flag.
3. Read the new `<case>.golden.json`. Does every finding make sense? Is anything
   missing? If the scanner is wrong and you are not fixing it in this PR,
   record it as a `known-gap` in the header (see below).
4. `scripts/verify.sh`.

## Updating goldens

A scanner change that moves findings shows up as a golden diff. Regenerate with
`-update`. **Golden diffs are reviewed like code.** Every added or removed line
in a `*.golden.json` is a behavior change that users will see. The PR
description must explain each one. A reviewer who sees an unexplained golden
change should block the PR. Deleting a case means deleting its golden too, and
the test fails on orphan goldens.

## Known gaps recorded in the corpus

The goldens capture **current** behavior, including these known-wrong results.
When a fix lands, flip the case's `known-gap` line back to `expect:` /
`expect-none:` and regenerate.

| Case | Gap |
| --- | --- |
| `gh-cache-poisoning-release` | **False negative.** `cicd-sec-4-cache-poisoning-release` misses a release that publishes via `goreleaser/goreleaser-action` (`args: release`). Only the `goreleaser release` run-script form counts as publishing. |
| `gh-release-no-cache-lookalike` | **False positive.** The same rule fires on `actions/setup-go` with `cache: false`, because it substring-matches `cache` in the `with:` block, which includes the opt-out the rule itself recommends. |
| `gh-issue-title-env-lookalike` | **False positive.** `cicd-sec-4-ppe-shell-injection` fires on `${{ github.event.issue.number }}` (an integer). The untrusted-context regex matches any `github.event.issue.*`. |
| `gh-pwn-request-prt-checkout`, `gh-workflow-run-artifact-poisoning` | **Noise.** `cicd-sec-4-ppe-shell-injection` fires on `with:` inputs of actions that don't evaluate code (`actions/checkout` `ref:` = head SHA, `download-artifact` `run-id:`). |
| `gl-quoted-var-lookalike` | **False positive.** `cicd-sec-4-gl-shell-injection` fires on a quoted `"$CI_COMMIT_TITLE"`. GitLab variables are env vars, so a quoted expansion is data. The rule is a substring match. |
| `gl-mr-unprotected-deploy` | **Debatable.** `cicd-sec-4-gl-shell-injection` also fires on an unquoted `$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME` in `git fetch`. The real risk on that line is the `gl-mr-target` finding. |
