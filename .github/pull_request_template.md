## What & why
<!-- One paragraph. Link the issue. -->

## SDLC artifacts
<!-- engineering/sdlc/<YYYY-MM-DD>-<slug>/  (intent / spec / plan), or "n/a: trivial" -->

## Scanner changes
- [ ] New or changed rule. True-negative (look-alike) cases are tested
- [ ] Auto-fix added or changed. It is idempotent and has a round-trip test
- [ ] CLI, output-format or exported API change. AGENTS.md and llms.txt are updated
- [ ] Companion `pipefort-cloud` PR (docs page / pin bump): <!-- link or "n/a" -->

## Evidence
- [ ] `scripts/verify.sh` is green locally
- [ ] Sample output (`go run . -p <fixture>`) pasted below when detection changed
