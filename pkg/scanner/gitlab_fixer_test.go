package scanner

import (
	"strings"
	"testing"
)

// TestFixGitLabDebugTraceRemovesEntry rescans, then fixes the literal
// debug-trace variable, then confirms the rule no longer fires.
func TestFixGitLabDebugTraceRemovesEntry(t *testing.T) {
	const y = `
variables:
  CI_DEBUG_TRACE: "true"
deploy:
  script: echo hi
`
	findings, err := ScanBytes(".gitlab-ci.yml", []byte(y))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	out, count, err := FixBytes([]byte(y), findings)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected at least one fix applied")
	}
	if strings.Contains(string(out), "CI_DEBUG_TRACE") {
		t.Errorf("CI_DEBUG_TRACE should have been removed, got:\n%s", string(out))
	}

	post, _ := ScanBytes(".gitlab-ci.yml", out)
	for _, f := range post {
		if f.RuleID == RuleGitLabDebugTrace {
			t.Errorf("debug-trace rule still fires after fix: %+v", f)
		}
	}
}

func TestFixGitLabAllowFailureRemovesEntry(t *testing.T) {
	const y = `
flaky:
  allow_failure: true
  script: echo hi
`
	findings, err := ScanBytes(".gitlab-ci.yml", []byte(y))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	out, count, err := FixBytes([]byte(y), findings)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected at least one fix applied")
	}
	if strings.Contains(string(out), "allow_failure") {
		t.Errorf("allow_failure should have been removed, got:\n%s", string(out))
	}
}

func TestFixGitLabMissingTimeoutInjects(t *testing.T) {
	const y = `
build:
  script: make all
`
	findings, err := ScanBytes(".gitlab-ci.yml", []byte(y))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	out, count, err := FixBytes([]byte(y), findings)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected at least one fix applied")
	}
	if !strings.Contains(string(out), "timeout: 30m") && !strings.Contains(string(out), "timeout: \"30m\"") {
		t.Errorf("expected `timeout: 30m` injection, got:\n%s", string(out))
	}

	post, _ := ScanBytes(".gitlab-ci.yml", out)
	for _, f := range post {
		if f.RuleID == RuleGitLabMissingTimeout {
			t.Errorf("missing-timeout rule still fires after fix: %+v", f)
		}
	}
}

// TestFixBytesRoutesGitLabFindings confirms the FixBytes router dispatches a
// findings batch carrying GitLab IDs to the GitLab fixer rather than running
// the GitHub dispatcher on a non-GitHub YAML.
func TestFixBytesRoutesGitLabFindings(t *testing.T) {
	const y = `
flaky:
  allow_failure: true
  script: echo hi
`
	findings := []Finding{{
		RuleID:   RuleGitLabAllowFailure,
		Category: "CICD-SEC-10",
		File:     ".gitlab-ci.yml",
		// Line/Column will be derived by scanning the doc inside the fixer.
		// Force a re-scan so the position is fresh.
	}}
	// Use ScanBytes to get accurate line/col.
	fresh, _ := ScanBytes(".gitlab-ci.yml", []byte(y))
	for _, f := range fresh {
		if f.RuleID == RuleGitLabAllowFailure {
			findings = []Finding{f}
			break
		}
	}

	out, count, err := FixBytes([]byte(y), findings)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 fix applied, got %d", count)
	}
	if strings.Contains(string(out), "allow_failure") {
		t.Errorf("router did not dispatch to GitLab fixer: %s", string(out))
	}
}
