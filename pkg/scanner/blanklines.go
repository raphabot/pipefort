package scanner

import "strings"

// yaml.v3 preserves comments across an Unmarshal→Encode round-trip but silently
// drops blank lines between nodes. Our fixers re-encode the whole document, so
// without help every blank separator line vanishes — producing noisy diffs
// where the only intended change is a one-line insertion.
//
// preserveBlankLines/restoreBlankLines bracket the round-trip: each blank line
// is swapped for a sentinel *comment* (which yaml.v3 keeps) before parsing, and
// swapped back to a blank line after encoding. Because the swap replaces a line
// in place — never inserting or deleting one — every physical line number is
// preserved, so the Line/Column positions the fixers match against stay valid.

const blankLineMarker = "#__pipefort_blank__#"

// preserveBlankLines replaces each blank (empty/whitespace-only) line with a
// sentinel comment indented to match the next non-blank line. Matching the
// following line's indentation keeps a blank line that sits *inside* a block
// scalar (e.g. a `run: |` script) from dedenting out of — and thereby
// terminating — that scalar. The trailing empty element produced by a final
// newline is left untouched so we don't append a stray comment.
func preserveBlankLines(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" {
			continue
		}
		// The final element after a trailing newline isn't a real blank line.
		if i == len(lines)-1 {
			continue
		}
		indent := ""
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) != "" {
				indent = lines[j][:len(lines[j])-len(strings.TrimLeft(lines[j], " \t"))]
				break
			}
		}
		lines[i] = indent + blankLineMarker
	}
	return []byte(strings.Join(lines, "\n"))
}

// restoreBlankLines turns sentinel-comment lines back into blank lines. It is
// tolerant of however yaml.v3 re-emits the comment (it may normalize spacing
// around the leading `#`), matching on the marker's payload rather than an
// exact string.
func restoreBlankLines(content []byte) []byte {
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if isBlankMarkerLine(line) {
			lines[i] = ""
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// isBlankMarkerLine reports whether a line is one of our sentinel comments,
// ignoring surrounding whitespace and any spaces yaml may insert after `#`.
func isBlankMarkerLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || trimmed[0] != '#' {
		return false
	}
	// Collapse the comment to its bare token: drop all '#' and spaces.
	bare := strings.NewReplacer("#", "", " ", "", "\t", "").Replace(trimmed)
	return bare == "__pipefort_blank__"
}
