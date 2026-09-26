---
name: fix-failing-tests
description: Use when asked to make failing tests or CI pass, or to fix a regression caught by tests, where the tests define correct behavior.
---

# Fix the code, not the tests

1. Turn on test protection, so a hook denies edits to existing `_test.go` and `testdata/` files:
   ```bash
   mkdir -p .claude/state && touch .claude/state/protect-tests
   ```
2. Loop: `scripts/verify.sh`, read the first failure, fix the
   code under test, and run it again. Change one cause at a time.
3. If you conclude a test is wrong (outdated contract, flaky timing), **stop**
   and explain it to the user with evidence. Do not edit it yourself.
4. When it is green, turn protection off:
   ```bash
   rm -f .claude/state/protect-tests
   ```
5. If this was a production bug, keep the reproducing test. It is now a
   permanent regression guard.
