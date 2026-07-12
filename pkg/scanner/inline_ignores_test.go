package scanner

import "testing"

// unpinnedCount returns how many unpinned-action findings ScanBytes produces.
func ruleCount(t *testing.T, wf string, rule RuleID) int {
	t.Helper()
	findings, err := ScanBytes(".github/workflows/test.yml", []byte(wf))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	n := 0
	for _, f := range findings {
		if f.RuleID == rule {
			n++
		}
	}
	return n
}

func TestInlineIgnoreSameLine(t *testing.T) {
	wf := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/login-action@v3  # pipefort: ignore[cicd-sec-3-unpinned-action]
`
	if got := ruleCount(t, wf, RuleUnpinnedAction); got != 0 {
		t.Errorf("same-line ignore should suppress, got %d findings", got)
	}
}

func TestInlineIgnoreLineAbove(t *testing.T) {
	wf := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      # pipefort: ignore[cicd-sec-3-unpinned-action]
      - uses: docker/login-action@v3
`
	if got := ruleCount(t, wf, RuleUnpinnedAction); got != 0 {
		t.Errorf("standalone-line-above ignore should suppress, got %d findings", got)
	}
}

func TestInlineIgnoreTrailingDoesNotLeakToNextLine(t *testing.T) {
	// The trailing comment on the first step must NOT suppress the second step's
	// finding (regression: a trailing comment is not a standalone "line above").
	wf := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v5  # pipefort: ignore[cicd-sec-3-unpinned-action]
      - uses: docker/login-action@v3
`
	if got := ruleCount(t, wf, RuleUnpinnedAction); got != 1 {
		t.Errorf("only the first (commented) step should be suppressed, got %d findings", got)
	}
}

func TestInlineIgnoreScopedToNamedRule(t *testing.T) {
	// Ignoring a different rule must not suppress the unpinned finding.
	wf := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/login-action@v3  # pipefort: ignore[cicd-sec-5-missing-permissions]
`
	if got := ruleCount(t, wf, RuleUnpinnedAction); got != 1 {
		t.Errorf("ignore scoped to another rule should not suppress unpinned, got %d", got)
	}
}

func TestInlineIgnoreBareSuppressesAll(t *testing.T) {
	wf := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/login-action@v3  # pipefort: ignore
`
	if got := ruleCount(t, wf, RuleUnpinnedAction); got != 0 {
		t.Errorf("bare ignore should suppress all rules on the line, got %d", got)
	}
}

func TestInlineIgnoreGitLab(t *testing.T) {
	// Inline ignores work on GitLab CI files too (applied inside ScanBytes).
	gl := `job:
  script:
    - curl https://x.sh | bash  # pipefort: ignore[best-prac-1-pipe-to-shell]
`
	findings, err := ScanBytes(".gitlab-ci.yml", []byte(gl))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	for _, f := range findings {
		if f.RuleID == RulePipeToShell {
			t.Errorf("GitLab inline ignore should suppress pipe-to-shell, got a finding at line %d", f.Line)
		}
	}
}
