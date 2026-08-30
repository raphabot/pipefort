package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// BEST-PRAC-5 — a multi-command shell script running without strict mode.
//
// GitHub's default shell for a `run:` step on Linux and macOS is `bash -e`.
// That is one of the three flags that matter, and not the interesting one:
//
//	-e            stop on a failing command          ← GitHub sets this
//	-u            stop on an unset variable          ← GitHub does not
//	-o pipefail   a pipeline fails if any stage does ← GitHub does not
//
// Without -o pipefail, `generate | tee out.txt` reports the exit status of
// `tee`, so a crash in `generate` produces an empty file and a green step.
// Without -u, a typo'd or unset variable expands to the empty string, so
// `rm -rf "$BUILD_DIR/"` becomes `rm -rf /`. Both fail silently and both
// produce a build that looks like it worked.
//
// GitLab has the same gap: the runner sets -e per script, not pipefail.
//
// Scoped tightly to keep it useful. Single-command steps are out — there is no
// pipeline to swallow and no sequencing to lose. Non-bash shells are out:
// pipefail is not POSIX sh, and pwsh/python have their own error models. What
// is left is the multi-command bash block, which is where the silent pass
// actually happens.
//
// LOW severity and the pedantic persona: it is a real gap, not a stylistic
// preference, but it fires on ordinary CI and must not crowd out security
// findings at the default tier.

// pipefailRe matches a `set` invocation that enables pipefail, in any of the
// spellings people use: `set -o pipefail`, `set -euo pipefail`,
// `set -eo pipefail`, `set -euxo pipefail`. The `o` may be its own flag or
// folded into a cluster — `-euo` is one token, not `-eu` plus `-o`, which is
// the case a naive `-o` match misses.
var pipefailRe = regexp.MustCompile(`(?m)^\s*set\s+-[a-zA-Z]*o[a-zA-Z]*\s+pipefail\b`)

// shebangRe matches an interpreter line, which must stay on line 1 to have any
// effect — strict mode is inserted after it, not before.
var shebangRe = regexp.MustCompile(`^#!\s*\S`)

// strictModeLine is what the fixer prepends and what the finding recommends.
const strictModeLine = "set -euo pipefail"

// CheckShellHardening flags multi-command bash `run:` blocks that do not
// enable strict mode.
func CheckShellHardening(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, jobWrap := range jobs {
		j := jobWrap
		windows := runsOnWindows(&j.Node.RunsOn)

		for _, step := range decodeSteps(j.Node) {
			s := step
			if s.Run.Value == "" {
				continue
			}
			shell := strings.TrimSpace(s.Shell.Value)
			if !isBashShell(shell, windows) {
				continue
			}
			// An explicit `shell:` string may carry the flags itself, e.g.
			// `bash -euo pipefail {0}` — that is already hardened.
			if strings.Contains(shell, "pipefail") {
				continue
			}
			if !isMultiCommandScript(s.Run.Value) {
				continue
			}
			if pipefailRe.MatchString(s.Run.Value) {
				continue
			}

			findings = append(findings, Finding{
				File:     file,
				Line:     s.Run.Line,
				Column:   s.Run.Column,
				Severity: SeverityLow,
				Category: "BEST-PRAC-5",
				RuleID:   RuleShellHardening,
				Title:    "Multi-command bash step runs without strict mode",
				Description: fmt.Sprintf(
					"Step %q in job %q runs several commands under bash without `%s`. "+
						"GitHub's default shell is `bash -e`: it stops on a failing command, but it does not set `-u` or `-o pipefail`. "+
						"Without pipefail, a failure on the left of a pipe is swallowed and the step passes green; without -u, an unset or misspelled variable expands to the empty string.",
					stepName(&s), j.ID, strictModeLine,
				),
				Recommendation: fmt.Sprintf("Add `%s` as the first line of the run block (after a shebang, if the script has one), or set `shell: bash -euo pipefail {0}` on the step.", strictModeLine),
			})
		}
	}
	return findings
}

// isBashShell reports whether a step's effective shell is bash.
//
// An empty `shell:` means the runner default, which is bash on Linux and macOS
// and pwsh on Windows. `sh` is excluded on purpose: pipefail is a bash
// extension, so recommending it there would produce a script that fails to
// start.
func isBashShell(shell string, windows bool) bool {
	if shell == "" {
		return !windows
	}
	return shell == "bash" || strings.HasPrefix(shell, "bash ")
}

// runsOnWindows reports whether a job's runner is a Windows image, in either
// the scalar or the label-list form.
func runsOnWindows(runsOn *yaml.Node) bool {
	if runsOn == nil {
		return false
	}
	switch runsOn.Kind {
	case yaml.ScalarNode:
		return strings.Contains(strings.ToLower(runsOn.Value), "windows")
	case yaml.SequenceNode:
		for _, it := range runsOn.Content {
			if strings.Contains(strings.ToLower(it.Value), "windows") {
				return true
			}
		}
	}
	return false
}

// isMultiCommandScript reports whether a script runs more than one command.
//
// Counts only lines that do something: blank lines and comments are neither a
// pipeline to swallow nor a step to lose ordering between, and counting them
// would flag a one-command block that happens to be documented.
func isMultiCommandScript(script string) bool {
	n := 0
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		if n > 1 {
			return true
		}
	}
	return false
}

// --- GitLab CI --------------------------------------------------------------

// checkGitLabShellHardening is the portable half: same RuleID, one finding per
// job, hardened by a `set -o pipefail` anywhere the job's shell will reach —
// its own before_script/script, or the top-level `default:` before_script that
// every job inherits.
func checkGitLabShellHardening(file string, jobs []glJob, defaultBefore []scriptLine) []Finding {
	defaultHardened := anyLineEnablesPipefail(defaultBefore)

	var findings []Finding
	for _, job := range jobs {
		j := job
		if len(j.Script) < 2 {
			// A single command has no pipeline to swallow. before_script is
			// not counted toward the length: it is setup, not the job's work.
			continue
		}
		if defaultHardened || anyLineEnablesPipefail(allScripts(j)) {
			continue
		}
		line, col := jobRulesAnchor(j)
		findings = append(findings, Finding{
			File:     file,
			Line:     line,
			Column:   col,
			Severity: SeverityLow,
			Category: "BEST-PRAC-5",
			RuleID:   RuleShellHardening,
			Title:    "Multi-command job runs without strict mode",
			Description: fmt.Sprintf(
				"Job %q runs several commands without `%s`. GitLab's runner stops on a failing command but does not set `-u` or `-o pipefail`, "+
					"so a failure on the left of a pipe is swallowed and the job passes green, and an unset or misspelled variable expands to the empty string.",
				j.ID, strictModeLine,
			),
			Recommendation: fmt.Sprintf("Add `%s` as the first entry of the job's `script:`, or once in a top-level `default: before_script:` so every job inherits it.", strictModeLine),
		})
	}
	return findings
}

func anyLineEnablesPipefail(lines []scriptLine) bool {
	for _, l := range lines {
		if pipefailRe.MatchString(l.Text) {
			return true
		}
	}
	return false
}

// --- Auto-fix ---------------------------------------------------------------

// fixShellHardening prepends strict mode to a run block, after a shebang when
// one is present — a shebang only works on line 1, so inserting above it would
// silently change which interpreter runs the script.
func fixShellHardening(rootNode *yaml.Node, f Finding) bool {
	runNode := findNodeByPosition(rootNode, f.Line, f.Column)
	if runNode == nil || runNode.Kind != yaml.ScalarNode {
		return false
	}
	if pipefailRe.MatchString(runNode.Value) {
		return false
	}

	lines := strings.Split(runNode.Value, "\n")
	at := 0
	if len(lines) > 0 && shebangRe.MatchString(strings.TrimSpace(lines[0])) {
		at = 1
	}
	indent := leadingWhitespace(firstCommandLine(lines[at:]))

	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:at]...)
	out = append(out, indent+strictModeLine)
	out = append(out, lines[at:]...)
	runNode.Value = strings.Join(out, "\n")
	// A single-line scalar becomes multi-line; force the literal block style so
	// the emitter does not fold it into one quoted string.
	runNode.Style = yaml.LiteralStyle
	runNode.Tag = ""
	return true
}

// firstCommandLine returns the first line that runs something, so the inserted
// line matches the script's own indentation rather than a blank line's.
func firstCommandLine(lines []string) string {
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			return l
		}
	}
	return ""
}

func leadingWhitespace(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// fixGitLabShellHardening inserts strict mode as the first entry of a job's
// `script:` sequence.
func fixGitLabShellHardening(jobNode *yaml.Node) bool {
	script := mappingValueByKey(jobNode, "script")
	if script == nil || script.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range script.Content {
		if pipefailRe.MatchString(item.Value) {
			return false
		}
	}
	entry := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: strictModeLine}
	script.Content = append([]*yaml.Node{entry}, script.Content...)
	return true
}
