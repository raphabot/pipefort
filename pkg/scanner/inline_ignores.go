package scanner

import (
	"regexp"
	"strings"
)

// Inline suppression comments let a workflow author silence a specific finding
// where it sits, zizmor-style:
//
//	- uses: actions/checkout@v4  # pipefort: ignore[cicd-sec-3-unpinned-action]
//
// or on the line above:
//
//	# pipefort: ignore[cicd-sec-3-unpinned-action]
//	- uses: actions/checkout@v4
//
// A bare `# pipefort: ignore` (no bracket) suppresses every rule at that
// location. Multiple rule IDs are comma-separated inside the brackets.
//
// Suppression is applied inside ScanBytes, so the CLI, the web scanner, the
// fixers' post-fix re-scan, and future PR checks all honor it with no extra
// wiring. It works line-by-line on the raw file bytes and is independent of the
// file-path globs in .pipefort.yml.

var reInlineIgnore = regexp.MustCompile(`#\s*pipefort:\s*ignore(?:\[([^\]]*)\])?`)

// inlineDirective is a parsed suppression comment. When All is true every rule
// on the target line is suppressed; otherwise only the listed rule IDs are.
// Standalone is true when the comment occupies its own line (only whitespace
// before the `#`); only standalone directives suppress the line *below* them —
// a trailing comment targets its own line, not the next step.
type inlineDirective struct {
	All        bool
	Rules      map[RuleID]bool
	Standalone bool
}

// suppresses reports whether this directive silences the given rule.
func (d inlineDirective) suppresses(rule RuleID) bool {
	if d.All {
		return true
	}
	return d.Rules[rule]
}

// CollectInlineIgnores parses the raw file content and returns a directive per
// line that carries a `# pipefort: ignore` comment (1-based line numbers).
func CollectInlineIgnores(content []byte) map[int]inlineDirective {
	out := map[int]inlineDirective{}
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		loc := reInlineIgnore.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		m := reInlineIgnore.FindStringSubmatch(line)
		// Standalone when only whitespace (or a bare YAML list dash) precedes
		// the comment — then it targets the line below rather than its own line.
		before := strings.TrimSpace(line[:loc[0]])
		d := inlineDirective{Standalone: before == "" || before == "-"}
		if strings.TrimSpace(m[1]) == "" && !strings.Contains(line, "[") {
			// Bare `# pipefort: ignore` with no brackets — suppress all rules.
			d.All = true
		} else {
			d.Rules = map[RuleID]bool{}
			for _, r := range strings.Split(m[1], ",") {
				if id := strings.TrimSpace(r); id != "" {
					d.Rules[RuleID(id)] = true
				}
			}
			// `# pipefort: ignore[]` (empty brackets) is treated as ignore-all
			// so an author can't accidentally create a no-op directive.
			if len(d.Rules) == 0 {
				d.All = true
			}
		}
		out[i+1] = d // 1-based line numbers to match Finding.Line
	}
	return out
}

// applyInlineIgnores drops findings suppressed by a `# pipefort: ignore`
// comment on the finding's own line or the line immediately above it. SYSTEM
// findings (empty RuleID) are never suppressed — a parse error must not be
// silenceable by a comment. Returns the input unchanged when there are no
// directives.
func applyInlineIgnores(findings []Finding, content []byte) []Finding {
	directives := CollectInlineIgnores(content)
	if len(directives) == 0 {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID != "" && f.Line > 0 {
			// Same-line directive (trailing or standalone) always applies.
			if d, ok := directives[f.Line]; ok && d.suppresses(f.RuleID) {
				continue
			}
			// The line above suppresses only if it is a standalone comment line.
			if d, ok := directives[f.Line-1]; ok && d.Standalone && d.suppresses(f.RuleID) {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}
