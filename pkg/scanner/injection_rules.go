package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Injection-depth checks (CICD-SEC-4 / CICD-SEC-1) that close blind spots the
// naive direct-interpolation PPE check (CheckPPE) misses:
//
//   - untrusted data reaching $GITHUB_ENV / $GITHUB_PATH, even laundered through
//     an intermediate env: var (the very pattern recommended to fix plain shell
//     injection does NOT make an environment-file write safe);
//   - `${{ env.X }}` re-interpolation where X holds untrusted data (a bypass of
//     the direct-only github.event.* match);
//   - spoofable `if:` gates comparing github.actor to a bot login.

// reGithubEnvWrite matches a shell write into the GITHUB_ENV / GITHUB_PATH files
// (redirect or `tee`), which persists values into later steps' environment/PATH.
var reGithubEnvWrite = regexp.MustCompile(`(?i)(>>?|tee(\s+-a)?)\s*"?\$\{?GITHUB_(ENV|PATH)\}?`)

// reEnvInterp matches an `${{ env.NAME }}` expression interpolation.
var reEnvInterp = regexp.MustCompile(`\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_\-]*)\s*\}\}`)

// reSpoofableActor matches an `if:` comparison of github.actor /
// github.triggering_actor to a bot login string (ending in "[bot]"), in either
// operand order.
var reSpoofableActor = regexp.MustCompile(`github\.(?:actor|triggering_actor)\s*==\s*'[^']*\[bot\]'|'[^']*\[bot\]'\s*==\s*github\.(?:actor|triggering_actor)`)

// taintedEnvVars returns the set of env var names (across the supplied env
// mapping nodes, later scopes overriding earlier) whose value interpolates an
// untrusted context — i.e. assigning the var laundered attacker-controlled data.
func taintedEnvVars(envNodes ...*yaml.Node) map[string]bool {
	tainted := map[string]bool{}
	for _, env := range envNodes {
		if env == nil || env.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(env.Content); i += 2 {
			name := env.Content[i].Value
			val := env.Content[i+1].Value
			if rePPEUntrustedCtx.MatchString(val) {
				tainted[name] = true
			} else {
				// A later, clean assignment untaints the name for this scope.
				delete(tainted, name)
			}
		}
	}
	return tainted
}

// referencesVar reports whether a shell snippet references env var name as
// $NAME or ${NAME}.
func referencesVar(s, name string) bool {
	for _, pat := range []string{"$" + name, "${" + name + "}"} {
		idx := strings.Index(s, pat)
		for idx >= 0 {
			// Ensure $NAME isn't a prefix of a longer identifier ($NAMES).
			end := idx + len(pat)
			if pat[1] == '{' || end >= len(s) || !isIdentChar(s[end]) {
				return true
			}
			next := strings.Index(s[idx+1:], pat)
			if next < 0 {
				break
			}
			idx = idx + 1 + next
		}
	}
	return false
}

func isIdentChar(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// CheckGitHubEnvInjection flags writes to $GITHUB_ENV / $GITHUB_PATH whose value
// derives from untrusted input — either interpolated directly, or laundered
// through a tainted env: var. Poisoning these files injects environment
// variables / PATH entries into every subsequent step (CICD-SEC-4).
func CheckGitHubEnvInjection(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			if s.Run.Value == "" {
				continue
			}
			tainted := taintedEnvVars(&workflow.Env, &jobWrap.Node.Env, &s.Env)

			for _, line := range strings.Split(s.Run.Value, "\n") {
				if !reGithubEnvWrite.MatchString(line) {
					continue
				}
				reason := ""
				if rePPEUntrustedCtx.MatchString(line) {
					reason = "interpolates untrusted event data directly"
				} else {
					for name := range tainted {
						if referencesVar(line, name) {
							reason = fmt.Sprintf("references $%s, which holds untrusted event data", name)
							break
						}
					}
				}
				if reason == "" {
					continue
				}
				findings = append(findings, Finding{
					File:     file,
					Line:     s.Run.Line,
					Column:   s.Run.Column,
					Severity: SeverityHigh,
					Category: "CICD-SEC-4",
					RuleID:   RuleGitHubEnvInjection,
					Title:    "Untrusted input written to GITHUB_ENV/GITHUB_PATH",
					Description: fmt.Sprintf(
						"Step %q in job %q writes to $GITHUB_ENV or $GITHUB_PATH with a value that %s. "+
							"Because these files set the environment and PATH for all later steps, an attacker can inject arbitrary variables (e.g. LD_PRELOAD, NODE_OPTIONS) or PATH entries and achieve code execution — even when the value is quoted for the current shell.",
						stepName(&s), jobWrap.ID, reason),
					Recommendation: "Do not write untrusted input into GITHUB_ENV/GITHUB_PATH. Validate/allowlist the value first, or keep it in a step-scoped env: var and consume it directly in the step that needs it.",
				})
				break // one finding per step is enough
			}
		}
	}
	return findings
}

// CheckPPELaundered extends PPE detection (same rule as CheckPPE) to untrusted
// data laundered through a tainted env: var and re-interpolated as `${{ env.X }}`
// in a run script or action input — a bypass of the direct github.event.* match.
func CheckPPELaundered(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			tainted := taintedEnvVars(&workflow.Env, &jobWrap.Node.Env, &s.Env)
			if len(tainted) == 0 {
				continue
			}

			report := func(text string, line, col int) {
				for _, m := range reEnvInterp.FindAllStringSubmatch(text, -1) {
					if tainted[m[1]] {
						findings = append(findings, Finding{
							File:     file,
							Line:     line,
							Column:   col,
							Severity: SeverityHigh,
							Category: "CICD-SEC-4",
							RuleID:   RulePPEShellInjection,
							Title:    "Poisoned Pipeline Execution (laundered shell injection)",
							Description: fmt.Sprintf(
								"Step %q in job %q re-interpolates ${{ env.%s }}, but env var %q was assigned untrusted event data. "+
									"Reading it back through the expression context (rather than as a $-shell variable) re-injects the attacker-controlled value as code.",
								stepName(&s), jobWrap.ID, m[1], m[1]),
							Recommendation: "Reference the env var as a shell variable ($VAR), never via ${{ env.VAR }}. Better, pass untrusted data through env: and consume it as $VAR directly without re-interpolation.",
						})
						return // one finding per step
					}
				}
			}

			if s.Run.Value != "" {
				report(s.Run.Value, s.Run.Line, s.Run.Column)
			}
			if s.With.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(s.With.Content); i += 2 {
					v := s.With.Content[i+1]
					if v.Kind == yaml.ScalarNode {
						report(v.Value, v.Line, v.Column)
					}
				}
			}
		}
	}
	return findings
}

// CheckSpoofableActorCondition flags an `if:` gate that compares github.actor or
// github.triggering_actor to a bot login as a security control. Those fields are
// spoofable in several trigger contexts, so they must not be the sole guard on
// privileged logic (CICD-SEC-1).
func CheckSpoofableActorCondition(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	emit := func(ifVal string, line, col int, scope string) {
		if ifVal == "" || !reSpoofableActor.MatchString(ifVal) {
			return
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     line,
			Column:   col,
			Severity: SeverityMedium,
			Category: "CICD-SEC-1",
			RuleID:   RuleSpoofableActorCondition,
			Title:    "Security decision based on a spoofable actor check",
			Description: fmt.Sprintf(
				"%s gates on a github.actor / github.triggering_actor comparison to a bot login. "+
					"The actor field is attacker-influenceable in several trigger contexts, so using it alone to authorize privileged steps can be bypassed.",
				scope),
			Recommendation: "Don't rely on github.actor for authorization. Gate on the event/trigger and permissions instead, and verify bot-authored changes by their signed commits or app identity rather than the actor login.",
		})
	}

	for _, jobWrap := range jobs {
		emit(jobWrap.Node.If.Value, jobWrap.Node.If.Line, jobWrap.Node.If.Column, fmt.Sprintf("Job %q", jobWrap.ID))

		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			emit(s.If.Value, s.If.Line, s.If.Column, fmt.Sprintf("Step %q in job %q", stepName(&s), jobWrap.ID))
		}
	}
	return findings
}
