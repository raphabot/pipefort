package scanner

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// fixGitLabBytes applies the GitLab YAML auto-fixers and returns the
// rewritten bytes plus the count of fixes applied. v1 covers the
// conservative trio: cicd-sec-7-gl-debug-trace (remove the env var),
// cicd-sec-10-gl-allow-failure (remove the key), and
// best-prac-2-gl-missing-timeout (inject `timeout: "30m"`).
//
// Returns (nil, 0, nil) when no findings matched — callers use this to skip
// opening an empty MR or writing an unchanged file.
func fixGitLabBytes(content []byte, findings []Finding) ([]byte, int, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(preserveBlankLines(content), &doc); err != nil {
		return nil, 0, fmt.Errorf("failed to parse GitLab YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, 0, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, 0, nil
	}

	jobs, _ := splitGitLabRoot(root)
	jobByID := map[string]*yaml.Node{}
	for _, j := range jobs {
		jobByID[j.ID] = j.Mapping
	}

	count := 0
	modified := false

	for _, f := range findings {
		switch f.RuleID {
		case RuleGitLabDebugTrace:
			// Remove the CI_DEBUG_TRACE / CI_DEBUG_SERVICES entry from
			// whichever variables: block carries it. f.Line/f.Column point
			// at the offending key node.
			if removeMapEntry(root, f.Line, f.Column) {
				count++
				modified = true
			}
		case RuleGitLabAllowFailure:
			// f.Line/Column point at the allow_failure value; the entry
			// removal helper walks parents to find the key/value pair.
			if removeMapEntry(root, f.Line, f.Column) {
				count++
				modified = true
			}
		case RuleGitLabMissingTimeout:
			// f.Line/Column point at the job key node; inject a sibling
			// `timeout: 30m` entry into the job mapping if absent.
			if jobNode := jobByIDAt(root, f.Line, f.Column); jobNode != nil {
				if !hasMapKey(jobNode, "timeout") {
					jobNode.Content = append(jobNode.Content,
						&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "timeout"},
						&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "30m"},
					)
					count++
					modified = true
				}
			}
		}
	}

	if !modified {
		return nil, 0, nil
	}

	var out strings.Builder
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, 0, fmt.Errorf("re-encode YAML: %w", err)
	}
	_ = enc.Close()
	return restoreBlankLines([]byte(out.String())), count, nil
}

// jobByIDAt finds the job whose key node sits at (line, col) and returns
// its value mapping node so the fixer can mutate it in place.
func jobByIDAt(root *yaml.Node, line, col int) *yaml.Node {
	for i := 0; i < len(root.Content); i += 2 {
		k := root.Content[i]
		v := root.Content[i+1]
		if k.Line == line && k.Column == col && v.Kind == yaml.MappingNode {
			return v
		}
	}
	return nil
}

// hasMapKey reports whether the given mapping has a child with the named key.
func hasMapKey(m *yaml.Node, key string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return true
		}
	}
	return false
}

// findingIsGitLab reports whether a Finding originated from a GitLab rule.
// Used by FixBytes to dispatch the right fixer.
func findingIsGitLab(f Finding) bool {
	return strings.Contains(string(f.RuleID), "-gl-")
}
