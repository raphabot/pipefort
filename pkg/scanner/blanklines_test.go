package scanner

import (
	"strings"
	"testing"
)

// The timeout fixer (BEST-PRAC-2) is purely additive: it appends
// `timeout-minutes: 30` to a job mapping. The rest of the file — including the
// blank lines separating sections and steps — must survive untouched. This is
// the regression for the noisy `+3 -11` diff where every blank line was dropped.
func TestFixBytesPreservesBlankLinesAndComments(t *testing.T) {
	src := `name: migrate

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  migrate:
    name: supabase db push
    runs-on: ubuntu-latest

    steps:
      - name: checkout
        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4

      - name: db push
        run: |
          supabase db push

          echo done
`
	findings, err := ScanBytes("migrate.yml", []byte(src))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var timeoutFindings []Finding
	for _, f := range findings {
		if f.RuleID == RuleMissingTimeout {
			timeoutFindings = append(timeoutFindings, f)
		}
	}
	if len(timeoutFindings) == 0 {
		t.Fatal("expected a BEST-PRAC-2 missing-timeout finding to drive the fix")
	}

	out, count, err := FixBytes([]byte(src), timeoutFindings)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if count == 0 || out == nil {
		t.Fatal("expected the timeout fix to apply")
	}
	got := string(out)

	// The intended change landed.
	if !strings.Contains(got, "timeout-minutes: 30") {
		t.Fatalf("expected timeout-minutes added, got:\n%s", got)
	}
	// Comments survived (they already did before this fix).
	if !strings.Contains(got, "# v4") {
		t.Fatalf("expected pinned-action comment preserved, got:\n%s", got)
	}
	// Blank separator lines survived — the actual regression. Count them.
	if blanks := countBlankLines(got); blanks < 5 {
		t.Fatalf("expected blank separator lines preserved (>=5), got %d:\n%s", blanks, got)
	}
	// The blank line *inside* the `run: |` block must remain blank (not turned
	// into a sentinel comment) and not corrupt the script.
	if !strings.Contains(got, "supabase db push\n\n          echo done") {
		t.Fatalf("expected blank line inside run block preserved, got:\n%s", got)
	}
	// No sentinel leaked into the output.
	if strings.Contains(got, "pipefort_blank") {
		t.Fatalf("blank-line sentinel leaked into output:\n%s", got)
	}
}

func TestPreserveRestoreBlankLinesRoundTrips(t *testing.T) {
	// restoreBlankLines must undo preserveBlankLines exactly for unparsed text.
	cases := []string{
		"a:\n\nb:\n",
		"a:\n  b: 1\n\n  c: 2\n",
		"no trailing newline\n\nx: 1",
	}
	for _, in := range cases {
		got := string(restoreBlankLines(preserveBlankLines([]byte(in))))
		if got != in {
			t.Fatalf("round-trip mismatch\n in: %q\nout: %q", in, got)
		}
	}
}

func countBlankLines(s string) int {
	n := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			line := s[start:i]
			if line == "" {
				n++
			}
			start = i + 1
		}
	}
	return n
}
