package scanner

import (
	"strings"
	"testing"
)

// --- CICD-SEC-1: pull_request + pull_request_target dual trigger ------------

func TestCheckPRTargetDualTrigger(t *testing.T) {
	cases := []struct {
		name         string
		yaml         string
		want         int
		wantSeverity Severity
		wantTitle    string
	}{
		{
			name: "both triggers in a list",
			yaml: `
on: [pull_request, pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`,
			want:         1,
			wantSeverity: SeverityMedium,
			wantTitle:    "trigger",
		},
		{
			name: "both triggers in a mapping",
			yaml: `
on:
  pull_request:
    branches: [main]
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`,
			want:         1,
			wantSeverity: SeverityMedium,
			wantTitle:    "trigger",
		},
		{
			name: "pull_request alone is fine",
			yaml: `
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`,
			want: 0,
		},
		{
			name: "pull_request_target alone is not this rule",
			yaml: `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`,
			want: 0,
		},
		{
			name: "head context read in an if under pull_request_target",
			yaml: `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    if: github.event.pull_request.head.repo.full_name == github.repository
    steps:
      - run: make test
`,
			want:         1,
			wantSeverity: SeverityHigh,
			wantTitle:    "head",
		},
		{
			name: "head context read in a step with: under pull_request_target",
			yaml: `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@v1
        with:
          branch: ${{ github.event.pull_request.head.ref }}
`,
			want:         1,
			wantSeverity: SeverityHigh,
			wantTitle:    "head",
		},
		{
			name: "workflow_run head context read",
			yaml: `
on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@v1
        with:
          sha: ${{ github.event.workflow_run.head_sha }}
`,
			want:         1,
			wantSeverity: SeverityHigh,
			wantTitle:    "head",
		},
		{
			name: "head context read under a plain pull_request is not privileged",
			yaml: `
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@v1
        with:
          branch: ${{ github.event.pull_request.head.ref }}
`,
			want: 0,
		},
		{
			name: "unrelated workflow is clean",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckPRTargetDualTrigger("test.yml", wf, jobs)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.want, got)
			}
			if tc.want == 0 {
				return
			}
			f := got[0]
			if f.RuleID != RulePRTargetDualTrigger {
				t.Errorf("got rule %q, want %q", f.RuleID, RulePRTargetDualTrigger)
			}
			if f.Category != "CICD-SEC-1" {
				t.Errorf("got category %q, want CICD-SEC-1", f.Category)
			}
			if f.Severity != tc.wantSeverity {
				t.Errorf("got severity %q, want %q", f.Severity, tc.wantSeverity)
			}
			if !strings.Contains(strings.ToLower(f.Title), tc.wantTitle) {
				t.Errorf("title %q does not mention %q", f.Title, tc.wantTitle)
			}
			if f.Line == 0 {
				t.Error("finding has no line")
			}
		})
	}
}

// A job that reads the head context in several places is one bridge to close,
// not five findings to triage.
func TestCheckPRTargetDualTriggerReportsOncePerJob(t *testing.T) {
	const y = `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    if: github.event.pull_request.head.repo.fork == false
    env:
      REF: ${{ github.event.pull_request.head.ref }}
    steps:
      - uses: some/action@v1
        with:
          sha: ${{ github.event.pull_request.head.sha }}
`
	wf, jobs := parseTestWorkflow(t, y)
	got := CheckPRTargetDualTrigger("test.yml", wf, jobs)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Description, "build") {
		t.Errorf("description should name the job: %s", got[0].Description)
	}
}

// Both halves can fire on one workflow: the trigger pair is a separate problem
// from the job that reads head content.
func TestCheckPRTargetDualTriggerBothHalves(t *testing.T) {
	const y = `
on: [pull_request, pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
	wf, jobs := parseTestWorkflow(t, y)
	got := CheckPRTargetDualTrigger("test.yml", wf, jobs)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
}

// --- auto-fix: partial, comment at the trigger block ------------------------

func TestFixPRTargetDualTriggerAnnotatesTrigger(t *testing.T) {
	const in = `on: [pull_request, pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: make test
`
	findings, err := ScanBytes(".github/workflows/ci.yml", []byte(in))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	var dual []Finding
	for _, f := range findings {
		if f.RuleID == RulePRTargetDualTrigger {
			dual = append(dual, f)
		}
	}
	if len(dual) != 1 {
		t.Fatalf("fixture produced %d dual-trigger findings, want 1", len(dual))
	}

	out, n, err := FixBytes([]byte(in), dual)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if n != 1 {
		t.Fatalf("applied %d fixes, want 1", n)
	}
	got := string(out)
	if !strings.Contains(got, prTargetFixMarker) {
		t.Errorf("output carries no marker comment:\n%s", got)
	}
	// Splitting the workflow or dropping a trigger changes semantics, so the
	// fix must leave both triggers in place.
	if !strings.Contains(got, "pull_request_target") || !strings.Contains(got, "pull_request,") {
		t.Errorf("fix altered the triggers instead of annotating them:\n%s", got)
	}
	if _, err := ScanBytes(".github/workflows/ci.yml", []byte(got)); err != nil {
		t.Fatalf("fixed output no longer parses: %v\n%s", err, got)
	}

	// Idempotent.
	again, n2, err := FixBytes([]byte(got), dual)
	if err != nil {
		t.Fatalf("FixBytes (2nd): %v", err)
	}
	if n2 != 0 {
		t.Errorf("second pass applied %d fixes, want 0:\n%s", n2, again)
	}
}

// The head-context half has no safe rewrite at all — the fix is for the
// trigger block only.
func TestFixPRTargetDualTriggerLeavesHeadReadAlone(t *testing.T) {
	const in = `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: some/action@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
	findings, err := ScanBytes(".github/workflows/ci.yml", []byte(in))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	var head []Finding
	for _, f := range findings {
		if f.RuleID == RulePRTargetDualTrigger {
			head = append(head, f)
		}
	}
	if len(head) != 1 {
		t.Fatalf("fixture produced %d findings, want 1", len(head))
	}
	_, n, err := FixBytes([]byte(in), head)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if n != 0 {
		t.Errorf("applied %d fixes to the head-context half, want 0", n)
	}
}
