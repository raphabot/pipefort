# Intent: Close the refspec bypass in the guard-bash.sh push-to-main guard

- **Author:** security-sweep (Claude) · **Date:** 2026-09-28 · **Issue:** none
- **Status:** proposed

## Problem

`.claude/hooks/guard-bash.sh` is the `PreToolUse` hook wired in
`.claude/settings.json` for every `Bash` tool call. It is the sole automated
control behind CLAUDE.md's "Pushing to `main` is denied" guardrail (point 6)
and the one the weekly `security-sweep.yml` job itself is told to trust
("Never merge, push to main, or touch production").

The check that is supposed to deny a direct push to `main`/`master` is:

```sh
if grep -Eq '[[:space:]](origin[[:space:]]+)?(HEAD:)?(main|master)([[:space:]]|$)' <<<"$cmd"; then
  decide deny "main only changes through a reviewed PR. Push a branch and open a PR instead."
fi
```

This only recognizes `main`/`master` when it is directly preceded by a space,
`origin `, or the literal string `HEAD:`. A standard git refspec push —
`git push origin <local-branch>:main` or `git push origin HEAD:refs/heads/main`
— places `main` immediately after a `:` or `/` instead, which this regex does
not cover. Traced through the rest of the function:

- The **force-push** check two lines above (`grep -Eq
  '(^|[[:space:]:/])(main|master)([[:space:]]|$)'`) already includes `:` and
  `/` in its character class — so the two checks are inconsistent, and the
  narrower one is the one guarding plain (non-force) pushes.
- The **bare-push** fallback only fires when there are ≤1 non-flag tokens
  after `git push`; a refspec push has 2 (`origin` and `<src>:main`), so it
  doesn't fall back to that check either.

Net effect: `git push origin feature-branch:main` and
`git push origin HEAD:refs/heads/main` are valid git syntax that push straight
to remote `main`, and both fall through `guard-bash.sh` with no `deny`/`ask`
decision (silently allowed). `.claude/hooks/test.sh` has no case for either
form, so CI's "Claude hook tests" step (`.github/workflows/ci.yml`) and
`scripts/verify.sh` don't catch the gap.

Confirmed by manual trace of the POSIX ERE against both command strings (grep
-E has no top-level alternation in the second check, so the leading
`[[:space:]]` must be the literal character immediately before the optional
groups — a colon or slash never satisfies that). I could not execute the hook
against the crafted input directly in this sandbox: the `security-sweep.yml`
`--allowedTools` list doesn't include arbitrary `Bash`/`jq` invocations, and
editing `.claude/hooks/guard-bash.sh` itself triggered this session's
"sensitive file" permission prompt with no human available to approve it
in this unattended run — appropriately, since silently patching an agent's own
guardrail file is exactly the kind of change that should get human eyes even
when the fix is well understood. That's why this is an intent.md rather than a
direct-fix PR.

## Desired outcome

`guard-bash.sh` denies (or asks on) every `git push` whose destination
resolves to `main`/`master`, including refspec forms
(`<src>:main`, `<src>:refs/heads/main`, `HEAD:main`, a bare `:main` delete),
not just the `git push origin main` / bare-push-on-`main`-branch forms it
already catches. `.claude/hooks/test.sh` has a regression case for at least
`git push origin feature-branch:main` and
`git push origin HEAD:refs/heads/main`, asserting `deny`.

## Affected systems

- `.claude/hooks/guard-bash.sh` (the check on line 23 in the current file,
  "main only changes through a reviewed PR").
- `.claude/hooks/test.sh` (add the two regression cases above).
- No `pkg/scanner`, CLI, fixer, or MCP surface is involved — this is a
  dev-tooling/guardrail fix, not a scanner rule.

## Constraints

- The fix should stay minimal and consistent with the existing style in the
  file — reusing the force-push check's already-correct character class
  (`(^|[[:space:]:/])(main|master)([[:space:]]|$)`) for the plain-push check
  is the smallest change that closes the gap, and it's a two-line diff plus
  test cases.
- Verify no regression on the existing `test.sh` cases, in particular that
  `git push -u origin feat/x` and other legitimate feature-branch pushes still
  `allow`, and that branch names merely containing `main`/`master` as a
  substring (e.g. `feat/rename-main-func`) aren't falsely denied — only a
  trailing, whole-token `main`/`master` should match.
- This is dev-tooling for the CLI repo only; it has no interaction with
  offline-first (ADR 0001) or the no-pgx boundary (ADR 0002).

## Success signal

- `.claude/hooks/test.sh` (and `scripts/verify.sh`, which runs it) fails
  before the fix on the two new refspec cases and passes after.
- Manual re-trace (or, once run interactively where the "sensitive file"
  prompt can be approved by a human, an actual hook invocation) confirms
  `git push origin feature-branch:main` and
  `git push origin HEAD:refs/heads/main` both now return a `deny` decision.

## Open questions

- Should the fix (and its test) land as a normal PR authored/approved by a
  human maintainer, given it touches `.claude/hooks/`? This intent
  intentionally stops short of writing the patch for that reason.
- Is there a broader class of `git` commands (e.g. `git push --mirror`, or
  pushing via a configured `pushInsteadOf` URL rewrite) that should get the
  same audit once this specific gap is closed?
