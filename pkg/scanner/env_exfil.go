package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// CICD-SEC-4 / CICD-SEC-6 — the two primitives a poisoned or malicious step
// uses to get secrets out of a runner.
//
// Neither is an exploit on its own. Both are the step an attacker adds once
// they have execution, and both are unusual enough in a real pipeline that
// finding one is worth a human look:
//
//   - Dumping the whole environment. Every secret the job was given is an
//     environment variable by the time the script runs, and workflow logs are
//     readable by anyone with read access to the repository. GitHub masks a
//     secret only where it recognises the exact value — an encoded dump walks
//     straight past that.
//   - Echoing a CI token. GITHUB_TOKEN and its siblings are minted per run and
//     carry the job's write scopes; a token in the log is a token anyone
//     watching the run can replay before it expires.
//
// Flag-only. There is no safe mechanical rewrite of an exfiltration primitive:
// deleting the line might remove a debugging aid the author wanted, and
// rewriting it would leave the same capability under a different spelling.
// The finding is the fix instruction.
//
// The encoded variants the issue calls for need no second obfuscation matcher.
// Encoding happens *downstream* of the primitive — `env | base64`,
// `echo $GITHUB_TOKEN | base64` — so the matchers below, which anchor on the
// primitive at the head of the pipe, already see through it. General
// obfuscation detection stays with cicd-sec-4-obfuscated-expression.

var (
	// reFullEnvDump matches a command that prints the entire environment.
	// Anchored at a command position (line start, or after a `;`, `|`, `&&`,
	// `then`, `do`) and required to be followed by end-of-command — a pipe, a
	// redirect, a separator, or nothing. That trailing requirement is what
	// separates enumeration from the two common innocent forms:
	// `env FOO=bar cmd` (run with a modified environment) and
	// `printenv HOME` (print one variable).
	reFullEnvDump = regexp.MustCompile(`(?i)(?:^|[;&|]|\bthen\b|\bdo\b)\s*(?:printenv|env)\s*(?:[|>&;]|$)`)

	// reExportDump matches the POSIX `export -p` / `declare -x` listing, which
	// prints every exported variable with its value.
	reExportDump = regexp.MustCompile(`(?i)(?:^|[;&|]|\bthen\b|\bdo\b)\s*(?:export\s+-p|declare\s+-x)\s*(?:[|>&;]|$)`)

	// reSetDump matches `set` piped or redirected. Bare `set` is excluded
	// deliberately: `set -euo pipefail` is the shell hardening this scanner
	// recommends elsewhere, and `set` with no output sink prints nothing
	// anywhere a log can capture.
	reSetDump = regexp.MustCompile(`(?i)(?:^|[;&|]|\bthen\b|\bdo\b)\s*set\s*(?:\||>)`)

	// reProcEnviron matches reading another process's environment block off
	// /proc — the same dump with the shell builtin taken out of the picture.
	reProcEnviron = regexp.MustCompile(`(?i)/proc/(?:self|\d+|\$\$|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/environ\b`)

	// ciTokenRefRe matches a reference to a runner-minted CI token, in either
	// the shell form ($GITHUB_TOKEN, ${GITHUB_TOKEN}) or the expression form
	// (${{ github.token }}). The `${{ secrets.GITHUB_TOKEN }}` spelling is
	// covered by cicd-sec-6-secret-in-run-output and left to it.
	ciTokenRefRe = regexp.MustCompile(`(?i)(\$\{?(GITHUB_TOKEN|ACTIONS_TOKEN|GITHUB_JOB_TOKEN|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN)\b\}?|\$\{\{\s*github\.token\s*\}\})`)

	// echoVerbRe matches a command that writes its argument somewhere a
	// human or a later step can read it. Encoders are included because
	// `echo $TOKEN | base64` and `base64 <<< "$TOKEN"` are the same act;
	// consumers that merely *use* a token (curl -H, gh, docker login) are
	// not, which is what keeps correct OIDC and API calls quiet.
	echoVerbRe = regexp.MustCompile(`(?i)\b(echo|printf|print|cat|tee|base64|xxd|od|hexdump)\b`)

	// exfilSinkRe matches a redirect into the step-output/env files, which
	// persist a value past the step that produced it.
	exfilSinkRe = regexp.MustCompile(`>>?\s*"?\$?\{?(GITHUB_OUTPUT|GITHUB_ENV|GITHUB_STEP_SUMMARY)\}?`)
)

// CheckEnvExfiltration flags run steps that enumerate the whole environment or
// echo a CI token.
func CheckEnvExfiltration(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, jobWrap := range jobs {
		j := jobWrap
		for _, step := range decodeSteps(j.Node) {
			s := step
			if s.Run.Value == "" {
				continue
			}

			dump, token := scanScriptForExfil(s.Run.Value)
			where := fmt.Sprintf("Step %q in job %q", stepName(&s), j.ID)

			if dump != "" {
				findings = append(findings, Finding{
					File:     file,
					Line:     s.Run.Line,
					Column:   s.Run.Column,
					Severity: SeverityHigh,
					Category: "CICD-SEC-6",
					RuleID:   RuleEnvExfil,
					Title:    "Run step dumps the whole environment",
					Description: fmt.Sprintf(
						"%s runs `%s`, which prints every environment variable the job holds. "+
							"Secrets passed to the job are environment variables by the time the script runs, and workflow logs are readable by anyone with read access to the repository. "+
							"GitHub masks a secret only where it recognises the exact value, so a dump — especially an encoded or reformatted one — walks past masking.",
						where, dump,
					),
					Recommendation: "Remove the environment dump. If you need to debug one variable, print that variable by name and confirm it holds nothing sensitive; never print the whole environment from a job that receives secrets.",
				})
			}

			if token != "" {
				findings = append(findings, Finding{
					File:     file,
					Line:     s.Run.Line,
					Column:   s.Run.Column,
					Severity: SeverityHigh,
					Category: "CICD-SEC-6",
					RuleID:   RuleEnvExfil,
					Title:    "Run step echoes a CI token",
					Description: fmt.Sprintf(
						"%s writes %s to the log or to a step output/env file. "+
							"That token is minted for this run and carries the job's write scopes, so anyone who can read the run can replay it before it expires.",
						where, token,
					),
					Recommendation: "Remove the echo. Pass the token to the consuming command through env: and let that command read it; if you need to prove a token is present, print its length rather than its value.",
				})
			}
		}
	}
	return findings
}

// scanScriptForExfil returns the environment-dump command and the CI token
// echoed by a run script, either empty when that half did not fire.
//
// Line-oriented rather than one regex over the whole block: the primitives are
// command-shaped, and matching them per line is what lets `env FOO=bar cmd` and
// `set -euo pipefail` stay quiet without a parser.
func scanScriptForExfil(script string) (dump string, token string) {
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		// A whole-line comment is documentation, not a command.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if dump == "" {
			switch {
			case reFullEnvDump.MatchString(line):
				dump = strings.TrimSpace(line)
			case reExportDump.MatchString(line):
				dump = strings.TrimSpace(line)
			case reSetDump.MatchString(line):
				dump = strings.TrimSpace(line)
			case reProcEnviron.MatchString(line):
				dump = strings.TrimSpace(line)
			}
		}

		if token == "" {
			if m := ciTokenRefRe.FindString(line); m != "" {
				if echoVerbRe.MatchString(line) || exfilSinkRe.MatchString(line) {
					token = m
				}
			}
		}

		if dump != "" && token != "" {
			break
		}
	}
	return dump, token
}
