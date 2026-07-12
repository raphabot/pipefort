package vcs

import (
	"strings"
	"testing"

	"github.com/raphabot/pipefort/pkg/scanner"
)

func TestChangeRequestBodyDocLink(t *testing.T) {
	body := ChangeRequestBody(scanner.RuleMissingTimeout, ".github/workflows/migrate.yml", 1)
	want := "https://docs.pipefort.com/rules/best-prac-2"
	if !strings.Contains(body, want) {
		t.Fatalf("PR body should link to %q, got:\n%s", want, body)
	}
	if strings.Contains(body, "pipefort.dev") {
		t.Fatalf("PR body must not reference the old pipefort.dev host:\n%s", body)
	}
}

func TestChangeRequestBodyUnknownRuleFallsBackToOverview(t *testing.T) {
	body := ChangeRequestBody(scanner.RuleID("does-not-exist"), "x.yml", 1)
	want := "https://docs.pipefort.com/rules/overview"
	if !strings.Contains(body, want) {
		t.Fatalf("unknown rule should fall back to %q, got:\n%s", want, body)
	}
}
