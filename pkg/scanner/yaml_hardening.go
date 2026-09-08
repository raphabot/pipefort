package scanner

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// CICD-SEC-1 — the pipeline definition treated as an input, rather than as
// something a parser is assumed to survive.
//
// Two hazards, both decided on the parsed document rather than by pattern
// matching on text:
//
//  1. A foreign YAML tag. `!!python/object/apply:os.system`, `!ruby/object`,
//     `!!php/object` and friends instruct a parser that honours them to
//     construct a language object — which for several parsers means calling
//     code. Nothing in a CI config has a legitimate reason to carry one. This
//     blocks.
//
//  2. Alias/anchor expansion that multiplies. The billion-laughs shape is an
//     anchor whose body is a list of aliases to the previous anchor, repeated:
//     each level multiplies, so a few lines expand to gigabytes and the parser
//     is the denial of service. This warns.
//
// The distinction that makes (2) usable: flat anchor reuse — one `.defaults`
// shared by sixty jobs — is the ordinary, correct way to share configuration,
// and it never multiplies no matter how many times it is used. A bomb REQUIRES
// nesting: an anchor that itself contains aliases to other anchors. So the rule
// keys on nesting first and size second, and a repository that leans hard on
// flat anchors is never flagged for it.
//
// Neither half has an auto-fix. A foreign tag is either an attack or a
// mistake, and both want a human. An expansion threshold is a judgement about
// intent that a rewrite cannot make.

// safeYAMLTags is the YAML core schema plus the tags a CI file legitimately
// carries. `!reference` is GitLab CI's own include mechanism and appears in
// ordinary .gitlab-ci.yml files; flagging it would make the rule unusable on
// the platform it ships for.
var safeYAMLTags = map[string]bool{
	"":            true,
	"!!str":       true,
	"!!int":       true,
	"!!float":     true,
	"!!bool":      true,
	"!!null":      true,
	"!!seq":       true,
	"!!map":       true,
	"!!binary":    true,
	"!!timestamp": true,
	"!!merge":     true, // the `<<:` merge key
	"!reference":  true, // GitLab CI
}

// maxAnchorExpansion is the expanded-node count above which a nested anchor
// graph is reported. Set well above what template inheritance produces (a
// two-level .gitlab-ci.yml hierarchy lands in the hundreds) and well below
// what a bomb reaches within a few more levels.
const maxAnchorExpansion = 5000

// expansionCeiling saturates the arithmetic so computing the size of a bomb
// cannot itself become one.
const expansionCeiling = 1 << 40

// CheckYAMLHardening flags foreign YAML tags and multiplying anchor
// expansions. It takes raw content because both hazards live in the document
// structure that a decode into WorkflowNode throws away.
func CheckYAMLHardening(file string, content []byte) []Finding {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		// Unparseable YAML is reported as a parse error by the caller; there
		// is no document here to make a claim about.
		return nil
	}

	findings := unsafeTagFindings(file, &doc)
	if f, ok := anchorExpansionFinding(file, &doc); ok {
		findings = append(findings, f)
	}
	return findings
}

// unsafeTagFindings reports every node carrying a tag outside the safe set,
// one finding per position.
func unsafeTagFindings(file string, doc *yaml.Node) []Finding {
	var findings []Finding
	seen := map[[2]int]bool{}

	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if !safeYAMLTags[n.Tag] {
			key := [2]int{n.Line, n.Column}
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					File:     file,
					Line:     n.Line,
					Column:   n.Column,
					Severity: SeverityHigh,
					Category: "CICD-SEC-1",
					RuleID:   RuleYAMLHardening,
					Title:    "Pipeline definition carries an unsafe YAML tag",
					Description: fmt.Sprintf(
						"The document declares the YAML tag %s. Tags in this family instruct a parser that honours them to construct a language-specific object, which for several parsers means executing code during load — turning a config file into a deserialization sink. "+
							"Nothing in a CI/CD pipeline definition has a legitimate reason to carry one.",
						n.Tag,
					),
					Recommendation: "Remove the tag and express the value as plain YAML (a string, number, list, or mapping). If you did not add it, treat the file as untrusted and find out who did — a foreign tag in a pipeline definition is an attack shape, not a style choice.",
					Confidence:     ConfidenceHigh,
				})
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(doc)
	return findings
}

// anchorExpansionFinding reports a nested anchor graph whose expansion
// multiplies past the threshold.
func anchorExpansionFinding(file string, doc *yaml.Node) (Finding, bool) {
	anchors := map[string]*yaml.Node{}
	collectAnchors(doc, anchors)
	if len(anchors) == 0 {
		return Finding{}, false
	}

	sizes := map[string]uint64{}
	depths := map[string]int{}
	var worst string
	var worstSize uint64
	var worstDepth int

	// Deterministic order so the reported anchor does not depend on map
	// iteration.
	names := make([]string, 0, len(anchors))
	for name := range anchors {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		size := expandedSize(anchors[name], anchors, sizes, map[string]bool{})
		depth := anchorDepth(name, anchors, depths, map[string]bool{})
		if depth >= 2 && size > worstSize {
			worst, worstSize, worstDepth = name, size, depth
		}
	}

	if worst == "" || worstSize <= maxAnchorExpansion {
		return Finding{}, false
	}
	return Finding{
		File:     file,
		Line:     anchors[worst].Line,
		Column:   anchors[worst].Column,
		Severity: SeverityMedium,
		Category: "CICD-SEC-1",
		RuleID:   RuleYAMLHardening,
		Title:    "Anchor expansion in the pipeline definition multiplies",
		Description: fmt.Sprintf(
			"Anchor &%s is nested %d levels deep in the alias graph and would expand to roughly %s nodes. "+
				"Each level of an anchor whose body is a list of aliases to the previous anchor multiplies the expanded size, which is the billion-laughs shape: a few lines of YAML become gigabytes in memory and the parser itself is the denial of service. "+
				"Flat anchor reuse — one template shared by many jobs — does not do this at any scale; multiplying requires the nesting seen here.",
			worst, worstDepth, formatExpansion(worstSize),
		),
		Recommendation: "Flatten the anchor graph so no anchor's body contains aliases to other anchors, or replace the nesting with explicit configuration. If this file is not yours, treat it as hostile input: it costs a few lines to write and exhausts whatever parses it.",
		Confidence:     ConfidenceMedium,
	}, true
}

func collectAnchors(n *yaml.Node, out map[string]*yaml.Node) {
	if n == nil {
		return
	}
	if n.Anchor != "" {
		out[n.Anchor] = n
	}
	for _, c := range n.Content {
		collectAnchors(c, out)
	}
}

// expandedSize is the number of nodes a subtree becomes once every alias is
// replaced by its anchor's content — what the parser would actually build.
// Memoized per anchor, saturating, and cycle-guarded.
func expandedSize(n *yaml.Node, anchors map[string]*yaml.Node, memo map[string]uint64, visiting map[string]bool) uint64 {
	if n == nil {
		return 0
	}
	if n.Kind == yaml.AliasNode {
		name := n.Value
		if v, ok := memo[name]; ok {
			return v
		}
		if visiting[name] {
			// A cycle cannot occur in a valid document, but a malformed one
			// must not hang the scanner.
			return expansionCeiling
		}
		target, ok := anchors[name]
		if !ok {
			return 1
		}
		visiting[name] = true
		v := expandedSize(target, anchors, memo, visiting)
		delete(visiting, name)
		memo[name] = v
		return v
	}

	total := uint64(1)
	for _, c := range n.Content {
		total += expandedSize(c, anchors, memo, visiting)
		if total >= expansionCeiling {
			return expansionCeiling
		}
	}
	return total
}

// anchorDepth is how many levels of anchor-to-anchor reference sit under an
// anchor. Flat reuse is depth 0 however widely it is used; the billion-laughs
// shape grows one level per stage.
func anchorDepth(name string, anchors map[string]*yaml.Node, memo map[string]int, visiting map[string]bool) int {
	if d, ok := memo[name]; ok {
		return d
	}
	node, ok := anchors[name]
	if !ok || visiting[name] {
		return 0
	}
	visiting[name] = true
	depth := 0
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.AliasNode {
			if d := anchorDepth(n.Value, anchors, memo, visiting) + 1; d > depth {
				depth = d
			}
			return
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(node)
	delete(visiting, name)
	memo[name] = depth
	return depth
}

// formatExpansion renders a saturating node count readably.
func formatExpansion(n uint64) string {
	if n >= expansionCeiling {
		return "more than a trillion"
	}
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1f billion", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1f million", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%s thousand", strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/1e3), ".0"))
	}
	return fmt.Sprintf("%d", n)
}
