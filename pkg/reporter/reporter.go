package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/raphabot/pipefort/pkg/scanner"
)

// ReportConsole pretty-prints findings to the console.
func ReportConsole(w io.Writer, findings []scanner.Finding) {
	if len(findings) == 0 {
		color.New(color.FgGreen, color.Bold).Fprintln(w, "\n✔ No security risks or vulnerabilities found in GitHub Actions workflows!")
		return
	}

	// Group findings by file
	grouped := make(map[string][]scanner.Finding)
	for _, f := range findings {
		grouped[f.File] = append(grouped[f.File], f)
	}

	// Sort file names for deterministic output
	var files []string
	for file := range grouped {
		files = append(files, file)
	}
	sort.Strings(files)

	// Define color styles
	highStyle := color.New(color.FgRed, color.Bold)
	mediumStyle := color.New(color.FgYellow, color.Bold)
	lowStyle := color.New(color.FgCyan, color.Bold)
	infoStyle := color.New(color.FgWhite, color.Bold)
	recStyle := color.New(color.FgGreen)
	fileStyle := color.New(color.FgMagenta, color.Bold, color.Underline)

	var highCount, mediumCount, lowCount, infoCount int

	fmt.Fprintln(w, "\n--- CI/CD SECURITY SCAN RESULTS ---")

	for _, file := range files {
		fmt.Fprintln(w)
		// Repository-settings findings carry the synthetic SettingsFile label
		// rather than a workflow path; surface them as their own group with a
		// human label.
		if file == scanner.SettingsFile {
			fileStyle.Fprintln(w, "Repository configuration")
		} else {
			fileStyle.Fprintf(w, "File: %s\n", file)
		}

		// Sort findings by line number
		fileFindings := grouped[file]
		sort.Slice(fileFindings, func(i, j int) bool {
			if fileFindings[i].Line == fileFindings[j].Line {
				return fileFindings[i].Column < fileFindings[j].Column
			}
			return fileFindings[i].Line < fileFindings[j].Line
		})

		for _, f := range fileFindings {
			var sevBadge string
			var badgeStyle *color.Color

			switch f.Severity {
			case scanner.SeverityHigh:
				sevBadge = "[HIGH]"
				badgeStyle = highStyle
				highCount++
			case scanner.SeverityMedium:
				sevBadge = "[MED ]"
				badgeStyle = mediumStyle
				mediumCount++
			case scanner.SeverityLow:
				sevBadge = "[LOW ]"
				badgeStyle = lowStyle
				lowCount++
			default:
				sevBadge = "[INFO]"
				badgeStyle = infoStyle
				infoCount++
			}

			// Print finding header. Workflow findings get a `Line X:Y` prefix;
			// settings findings (line == 0) omit it — there is no source line.
			if f.Line > 0 {
				fmt.Fprintf(w, "  Line %d:%d ", f.Line, f.Column)
			} else {
				fmt.Fprint(w, "  ")
			}
			badgeStyle.Fprint(w, sevBadge)
			color.New(color.Bold).Fprintf(w, " (%s) %s", f.Category, f.Title)
			// Tag non-certain findings so heuristic hits read as such. HIGH
			// (and legacy unstamped) confidence stays untagged to keep the
			// common case quiet.
			if f.Confidence == scanner.ConfidenceMedium || f.Confidence == scanner.ConfidenceLow {
				color.New(color.Faint).Fprintf(w, " [confidence: %s]", strings.ToLower(string(f.Confidence)))
			}
			fmt.Fprintln(w)

			// Print description
			fmt.Fprintf(w, "    Description: %s\n", f.Description)

			// Print recommendation
			fmt.Fprint(w, "    Remediation: ")
			recStyle.Fprintln(w, f.Recommendation)
			fmt.Fprintln(w)
		}
	}

	// Print summary
	fmt.Fprintln(w, "-----------------------------------")
	summaryMsg := fmt.Sprintf("Scan Summary: %d High, %d Medium, %d Low, %d Info findings.",
		highCount, mediumCount, lowCount, infoCount)

	if highCount > 0 || mediumCount > 0 {
		color.New(color.FgRed, color.Bold).Fprintf(w, "✖ %s\n\n", summaryMsg)
	} else if lowCount > 0 {
		color.New(color.FgYellow, color.Bold).Fprintf(w, "⚠ %s\n\n", summaryMsg)
	} else {
		color.New(color.FgGreen, color.Bold).Fprintf(w, "✔ %s\n\n", summaryMsg)
	}
}

// ReportJSON exports findings in JSON format.
func ReportJSON(w io.Writer, findings []scanner.Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

// jsonReport is the machine-readable output shape that carries both the flat
// findings list and the correlated toxic combinations ("Attacker Mind"). Note
// this replaces the historical bare-array JSON shape — see docs/cli output.
type jsonReport struct {
	Findings          []scanner.Finding    `json:"findings"`
	ToxicCombinations []scanner.ToxicCombo `json:"toxic_combinations"`
}

// ReportJSONWithCombos exports findings plus detected toxic combinations as a
// single JSON object. Both fields are always present (never null) so consumers
// can rely on the shape.
func ReportJSONWithCombos(w io.Writer, findings []scanner.Finding, combos []scanner.ToxicCombo) error {
	if findings == nil {
		findings = []scanner.Finding{}
	}
	if combos == nil {
		combos = []scanner.ToxicCombo{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonReport{Findings: findings, ToxicCombinations: combos})
}

// ReportCombos pretty-prints the "Attacker Mind" toxic-combination section to
// the console. It prints nothing when there are no combinations so clean scans
// stay quiet.
func ReportCombos(w io.Writer, combos []scanner.ToxicCombo) {
	if len(combos) == 0 {
		return
	}

	critStyle := color.New(color.FgHiRed, color.Bold)
	highStyle := color.New(color.FgRed, color.Bold)
	titleStyle := color.New(color.Bold)
	chainStyle := color.New(color.FgHiMagenta)
	breakStyle := color.New(color.FgGreen)

	color.New(color.FgHiRed, color.Bold).Fprintln(w, "\n--- ATTACKER MIND — TOXIC COMBINATIONS ---")
	fmt.Fprintln(w, "Findings that chain into a higher-impact compromise:")

	for _, c := range combos {
		badgeStyle := highStyle
		if c.Severity == scanner.ComboCritical {
			badgeStyle = critStyle
		}

		fmt.Fprintln(w)
		badgeStyle.Fprintf(w, "[%s]", c.Severity)
		titleStyle.Fprintf(w, " %s", c.Title)
		if c.Scope == scanner.ScopeFile && c.File != "" {
			fmt.Fprintf(w, " (%s)", c.File)
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "  Impact: %s\n", c.Impact)

		// ASCII attack chain: stage titles joined by arrows.
		if len(c.Stages) > 0 {
			titles := make([]string, 0, len(c.Stages))
			for _, s := range c.Stages {
				titles = append(titles, s.Title)
			}
			fmt.Fprint(w, "  Chain:  ")
			chainStyle.Fprintln(w, strings.Join(titles, " → "))
		}

		// Ingredient findings with file:line.
		fmt.Fprintln(w, "  Ingredients:")
		for _, comp := range c.Components {
			loc := comp.Finding.File
			if comp.Finding.Line > 0 {
				loc = fmt.Sprintf("%s:%d", comp.Finding.File, comp.Finding.Line)
			}
			fmt.Fprintf(w, "    - %s (%s)\n", comp.RuleID, loc)
		}

		fmt.Fprint(w, "  Break the chain: ")
		breakStyle.Fprintln(w, c.BreakChain)
	}
	fmt.Fprintln(w)
}
