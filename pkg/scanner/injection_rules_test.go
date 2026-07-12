package scanner

import "testing"

func countRule(findings []Finding, id RuleID) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == id {
			n++
		}
	}
	return n
}

func TestCheckGitHubEnvInjection(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{
			name: "direct untrusted context into GITHUB_ENV",
			yaml: `
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TITLE=${{ github.event.issue.title }}" >> $GITHUB_ENV
`,
			want: 1,
		},
		{
			name: "laundered through a tainted step env var",
			yaml: `
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "X=$TITLE" >> $GITHUB_ENV
`,
			want: 1,
		},
		{
			name: "tainted var into GITHUB_PATH",
			yaml: `
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      DIR: ${{ github.head_ref }}
    steps:
      - run: echo "$DIR" >> $GITHUB_PATH
`,
			want: 1,
		},
		{
			name: "static write is clean",
			yaml: `
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "FOO=bar" >> $GITHUB_ENV
`,
			want: 0,
		},
		{
			name: "tainted var used as shell var without env-file write is not this rule",
			yaml: `
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "$TITLE"
`,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := countRule(CheckGitHubEnvInjection("ci.yml", wf, jobs), RuleGitHubEnvInjection)
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCheckPPELaundered(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{
			name: "env.X re-interpolation of a tainted var",
			yaml: `
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "${{ env.TITLE }}"
`,
			want: 1,
		},
		{
			name: "shell-var reference is the safe pattern (not flagged)",
			yaml: `
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "$TITLE"
`,
			want: 0,
		},
		{
			name: "untainted env var re-interpolation is clean",
			yaml: `
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      FOO: bar
    steps:
      - run: echo "${{ env.FOO }}"
`,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := countRule(CheckPPELaundered("ci.yml", wf, jobs), RulePPEShellInjection)
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCheckSpoofableActorCondition(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{
			name: "job-level actor==bot",
			yaml: `
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - run: echo hi
`,
			want: 1,
		},
		{
			name: "step-level triggering_actor==bot, reversed operands",
			yaml: `
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - if: "'renovate[bot]' == github.triggering_actor"
        run: echo hi
`,
			want: 1,
		},
		{
			name: "non-bot actor comparison is not flagged",
			yaml: `
on: pull_request
jobs:
  j:
    runs-on: ubuntu-latest
    if: github.actor == 'octocat'
    steps:
      - run: echo hi
`,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := countRule(CheckSpoofableActorCondition("ci.yml", wf, jobs), RuleSpoofableActorCondition)
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestReferencesVar(t *testing.T) {
	if !referencesVar(`echo "$TITLE" >> x`, "TITLE") {
		t.Error("should match $TITLE")
	}
	if !referencesVar(`echo "${TITLE}"`, "TITLE") {
		t.Error("should match ${TITLE}")
	}
	if referencesVar(`echo "$TITLES"`, "TITLE") {
		t.Error("should not match $TITLE as a prefix of $TITLES")
	}
}
