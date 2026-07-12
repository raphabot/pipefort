package scanner

import (
	"strings"
	"testing"
)

// --- CICD-SEC-2: Long-lived PAT --------------------------------------------

func TestCheckLongLivedPAT(t *testing.T) {
	cases := []struct {
		name       string
		yaml       string
		wantCount  int
		wantRule   RuleID
		wantSecret string // substring expected in the finding description
	}{
		{
			name: "PAT in step env triggers",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: gh repo create
        env:
          GH_TOKEN: ${{ secrets.MY_GH_PAT }}
`,
			wantCount:  1,
			wantRule:   RuleLongLivedPAT,
			wantSecret: "MY_GH_PAT",
		},
		{
			name: "PERSONAL_ACCESS_TOKEN in with: triggers",
			yaml: `
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          token: ${{ secrets.RELEASE_PERSONAL_ACCESS_TOKEN }}
`,
			wantCount:  1,
			wantRule:   RuleLongLivedPAT,
			wantSecret: "RELEASE_PERSONAL_ACCESS_TOKEN",
		},
		{
			name: "GITHUB_TOKEN is not flagged",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`,
			wantCount: 0,
		},
		{
			name: "Unrelated secret is not flagged",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
`,
			wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckLongLivedPAT("test.yml", wf, jobs)
			if len(got) != tc.wantCount {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.wantCount, got)
			}
			if tc.wantCount == 0 {
				return
			}
			if got[0].RuleID != tc.wantRule {
				t.Errorf("got rule %q, want %q", got[0].RuleID, tc.wantRule)
			}
			if got[0].Category != "CICD-SEC-2" {
				t.Errorf("got category %q, want CICD-SEC-2", got[0].Category)
			}
			if !strings.Contains(got[0].Description, tc.wantSecret) {
				t.Errorf("description missing secret name %q: %s", tc.wantSecret, got[0].Description)
			}
		})
	}
}

// --- CICD-SEC-7: Debug logging ---------------------------------------------

func TestCheckDebugLoggingEnabled(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantCount int
	}{
		{
			name: "ACTIONS_STEP_DEBUG true at workflow level triggers",
			yaml: `
on: push
env:
  ACTIONS_STEP_DEBUG: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 1,
		},
		{
			name: "ACTIONS_RUNNER_DEBUG \"1\" at step level triggers",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          ACTIONS_RUNNER_DEBUG: "1"
`,
			wantCount: 1,
		},
		{
			name: "ACTIONS_STEP_DEBUG false is fine",
			yaml: `
on: push
env:
  ACTIONS_STEP_DEBUG: "false"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 0,
		},
		{
			name: "Unrelated env var is fine",
			yaml: `
on: push
env:
  MY_FLAG: "true"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckDebugLoggingEnabled("test.yml", wf, jobs)
			if len(got) != tc.wantCount {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.wantCount, got)
			}
			if tc.wantCount > 0 {
				if got[0].Category != "CICD-SEC-7" {
					t.Errorf("got category %q, want CICD-SEC-7", got[0].Category)
				}
				if got[0].Severity != SeverityHigh {
					t.Errorf("got severity %q, want HIGH", got[0].Severity)
				}
			}
		})
	}
}

// --- CICD-SEC-8: Unfiltered repository_dispatch ----------------------------

func TestCheckRepoDispatchUnfiltered(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantCount int
	}{
		{
			name: "scalar on: repository_dispatch triggers",
			yaml: `
on: repository_dispatch
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 1,
		},
		{
			name: "sequence on: includes repository_dispatch triggers",
			yaml: `
on: [push, repository_dispatch]
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 1,
		},
		{
			name: "mapping with empty types triggers",
			yaml: `
on:
  repository_dispatch:
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 1,
		},
		{
			name: "mapping with explicit types is fine",
			yaml: `
on:
  repository_dispatch:
    types: [run-tests]
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 0,
		},
		{
			name: "no repository_dispatch is fine",
			yaml: `
on: push
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckRepoDispatchUnfiltered("test.yml", wf, jobs)
			if len(got) != tc.wantCount {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.wantCount, got)
			}
			if tc.wantCount > 0 && got[0].Category != "CICD-SEC-8" {
				t.Errorf("got category %q, want CICD-SEC-8", got[0].Category)
			}
		})
	}
}

// --- CICD-SEC-9: Download without checksum ---------------------------------

func TestCheckDownloadWithoutChecksum(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantCount int
	}{
		{
			name: "curl tar.gz with no verification triggers",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -L https://example.com/tool.tar.gz -o tool.tar.gz
          tar xzf tool.tar.gz
`,
			wantCount: 1,
		},
		{
			name: "wget zip with sha256sum -c is fine",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          wget https://example.com/x.zip
          echo "deadbeef  x.zip" | sha256sum -c -
`,
			wantCount: 0,
		},
		{
			name: "curl binary with cosign verify-blob is fine",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -LO https://example.com/tool
          cosign verify-blob --signature tool.sig tool
`,
			wantCount: 0,
		},
		{
			name: "curl to a JSON file is fine (not a binary/archive)",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s https://api.example.com/data.json -o data.json
`,
			wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckDownloadWithoutChecksum("test.yml", wf, jobs)
			if len(got) != tc.wantCount {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.wantCount, got)
			}
			if tc.wantCount > 0 && got[0].Category != "CICD-SEC-9" {
				t.Errorf("got category %q, want CICD-SEC-9", got[0].Category)
			}
		})
	}
}

// --- CICD-SEC-10: Job-level continue-on-error -------------------------------

func TestCheckContinueOnErrorJob(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantCount int
	}{
		{
			name: "job continue-on-error: true triggers",
			yaml: `
on: push
jobs:
  flaky:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: false
`,
			wantCount: 1,
		},
		{
			name: "job continue-on-error: false is fine",
			yaml: `
on: push
jobs:
  ok:
    runs-on: ubuntu-latest
    continue-on-error: false
    steps:
      - run: echo hi
`,
			wantCount: 0,
		},
		{
			name: "step-level continue-on-error is fine (job-scoped check)",
			yaml: `
on: push
jobs:
  ok:
    runs-on: ubuntu-latest
    steps:
      - run: maybe
        continue-on-error: true
`,
			wantCount: 0,
		},
		{
			name: "expression-driven value is not flagged",
			yaml: `
on: push
jobs:
  conditional:
    runs-on: ubuntu-latest
    continue-on-error: ${{ github.event_name == 'schedule' }}
    steps:
      - run: maybe
`,
			wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckContinueOnErrorJob("test.yml", wf, jobs)
			if len(got) != tc.wantCount {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.wantCount, got)
			}
			if tc.wantCount > 0 && got[0].Category != "CICD-SEC-10" {
				t.Errorf("got category %q, want CICD-SEC-10", got[0].Category)
			}
		})
	}
}

// --- CICD-SEC-6 (extension): Secret printed to logs / written to output ------

func TestCheckSecretInRunOutput(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{
			name: "echo of a secret triggers",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.API_KEY }}"
`,
			want: 1,
		},
		{
			name: "secret written to GITHUB_OUTPUT triggers",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "key=${{ secrets.API_KEY }}" >> "$GITHUB_OUTPUT"
`,
			want: 1,
		},
		{
			name: "legacy set-output of a secret triggers",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::set-output name=tok::${{ secrets.TOKEN }}"
`,
			want: 1,
		},
		{
			name: "plain assignment to env var does not trigger",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          API_KEY: ${{ secrets.API_KEY }}
        run: curl --oauth2-bearer "$API_KEY" https://example.com
`,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckSecretInRunOutput("test.yml", wf, jobs)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(got), tc.want, got)
			}
			if tc.want > 0 {
				if got[0].RuleID != RuleSecretInRunOutput {
					t.Errorf("rule = %q, want %q", got[0].RuleID, RuleSecretInRunOutput)
				}
				if got[0].Category != "CICD-SEC-6" {
					t.Errorf("category = %q, want CICD-SEC-6", got[0].Category)
				}
			}
		})
	}
}
