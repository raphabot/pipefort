package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FixFindings groups findings by file, applies fixes to each file's YAML AST, and writes it back.
func FixFindings(targetPath string, findings []Finding) (int, error) {
	// Group findings by file path
	grouped := make(map[string][]Finding)
	for _, f := range findings {
		grouped[f.File] = append(grouped[f.File], f)
	}

	totalFixed := 0
	for file, fileFindings := range grouped {
		// If path is relative, resolve it relative to the execution directory
		// We'll trust the path in the finding is correct (either absolute or relative to Cwd)
		fixes, err := FixFile(file, fileFindings)
		if err != nil {
			return totalFixed, fmt.Errorf("failed to fix file %s: %w", file, err)
		}
		totalFixed += fixes
	}

	return totalFixed, nil
}

// FixFile parses a single YAML file, applies AST modifications based on
// findings, and saves in-place. Thin wrapper around FixBytes — exists so the
// CLI's --fix path keeps its current behaviour while the web app uses the
// in-memory primitive directly.
func FixFile(filePath string, findings []Finding) (int, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read file: %w", err)
	}
	newContent, fixesCount, err := FixBytes(content, findings)
	if err != nil {
		return 0, err
	}
	if newContent == nil {
		return 0, nil
	}
	if err := os.WriteFile(filePath, newContent, 0644); err != nil {
		return 0, fmt.Errorf("failed to write updated file: %w", err)
	}
	return fixesCount, nil
}

// FixBytes applies the auto-fix dispatcher to a CI YAML's content in-memory
// and returns the mutated bytes plus a count of fixes applied. Returns
// (nil, 0, nil) when no fix matched — callers can use this to skip opening
// an empty PR/MR or writing an unchanged file.
//
// Findings are split by platform via the RuleID suffix (`-gl-` → GitLab,
// otherwise GitHub). Mixed batches are rare (findings come from one file),
// so we dispatch the whole batch to whichever fixer matches the first
// platform-tagged finding; the other side's findings fall through unhandled.
func FixBytes(content []byte, findings []Finding) ([]byte, int, error) {
	for _, f := range findings {
		if findingIsGitLab(f) {
			return fixGitLabBytes(content, findings)
		}
	}
	return fixGitHubBytes(content, findings)
}

// fixGitHubBytes is the original GitHub-workflow fixer dispatcher. Renamed
// from FixBytes to make room for the cross-platform router above.
func fixGitHubBytes(content []byte, findings []Finding) ([]byte, int, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(preserveBlankLines(content), &doc); err != nil {
		return nil, 0, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, 0, nil
	}

	rootNode := doc.Content[0]
	if rootNode.Kind != yaml.MappingNode {
		return nil, 0, nil
	}

	fixesCount := 0

	// Track if we need to re-encode the document
	modified := false

	for _, f := range findings {
		switch f.Category {
		case "CICD-SEC-5": // PBAC - Missing permissions
			_, permNode, _ := findMapKey(rootNode, "permissions")
			if permNode == nil {
				valNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   "!!str",
					Value: "read-all",
				}
				insertMapNode(rootNode, "permissions", valNode)
				fixesCount++
				modified = true
			}

		case "CICD-SEC-1": // Insufficient flow control — dispatch on rule.
			switch f.RuleID {
			case RuleCheckoutPersistCreds:
				if fixCheckoutPersistCredentials(rootNode, f) {
					fixesCount++
					modified = true
				}
			case RulePPECheckout:
				// Only the dangerous-checkout rule rewrites the trigger; other
				// CICD-SEC-1 rules (e.g. workflow_run artifact poisoning) are
				// flag-only and must not have the trigger mangled.
				_, onNode, _ := findMapKey(rootNode, "on")
				if onNode != nil && fixPullRequestTarget(onNode) {
					fixesCount++
					modified = true
				}
			case RuleUnsoundCondition:
				ifNode := findNodeByPosition(rootNode, f.Line, f.Column)
				if ifNode != nil && ifNode.Kind == yaml.ScalarNode && fixUnsoundCondition(ifNode) {
					fixesCount++
					modified = true
				}
			}

		case "BEST-PRAC-2": // Timeout missing
			_, jobsNode, _ := findMapKey(rootNode, "jobs")
			if jobsNode != nil && jobsNode.Kind == yaml.MappingNode {
				for i := 0; i < len(jobsNode.Content); i += 2 {
					kNode := jobsNode.Content[i]
					vNode := jobsNode.Content[i+1]
					if kNode.Line == f.Line && kNode.Column == f.Column && vNode.Kind == yaml.MappingNode {
						hasTimeout := false
						for j := 0; j < len(vNode.Content); j += 2 {
							if vNode.Content[j].Value == "timeout-minutes" {
								hasTimeout = true
								break
							}
						}
						if !hasTimeout {
							keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "timeout-minutes"}
							valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "30"}
							vNode.Content = append(vNode.Content, keyNode, valNode)
							fixesCount++
							modified = true
						}
					}
				}
			}

		case "CICD-SEC-3": // Unpinned Action
			usesNode := findNodeByPosition(rootNode, f.Line, f.Column)
			if usesNode != nil && usesNode.Kind == yaml.ScalarNode {
				if fixUnpinnedAction(usesNode) {
					fixesCount++
					modified = true
				}
			}

		case "CICD-SEC-6": // Hardcoded Secret
			secretNode := findNodeByPosition(rootNode, f.Line, f.Column)
			if secretNode == nil || secretNode.Kind != yaml.ScalarNode {
				break
			}
			parent := findParentMappingNode(rootNode, secretNode)
			if parent == nil {
				break
			}
			idx := -1
			for i, child := range parent.Content {
				if child == secretNode {
					idx = i
					break
				}
			}
			if idx <= 0 || idx%2 != 1 {
				break
			}
			keyNode := parent.Content[idx-1]
			if keyNode.Value == "run" {
				// Inline-script case: hoist the literal into the step's env block.
				// Parent of the run node is the step mapping itself.
				if fixHardcodedSecretInRun(secretNode, parent) {
					fixesCount++
					modified = true
				}
				break
			}
			// Env-block case: substitute the literal with a secrets-context expression.
			secretNode.Value = fmt.Sprintf("${{ secrets.%s }}", strings.ToUpper(keyNode.Value))
			// Reset the scalar style so the substituted expression is
			// emitted plain (the original literal was double-quoted, which
			// would otherwise wrap the ${{ ... }} reference in quotes).
			secretNode.Style = 0
			secretNode.Tag = ""
			fixesCount++
			modified = true

		case "BEST-PRAC-4": // Missing concurrency guard
			if _, c, _ := findMapKey(rootNode, "concurrency"); c == nil {
				group := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "${{ github.workflow }}-${{ github.ref }}"}
				group.Style = yaml.DoubleQuotedStyle
				cancel := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}
				concNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				setMapKey(concNode, "group", group)
				setMapKey(concNode, "cancel-in-progress", cancel)
				insertMapNode(rootNode, "concurrency", concNode)
				fixesCount++
				modified = true
			}

		case "CICD-SEC-7": // Insecure System Configuration - debug logging
			if removeMapEntry(rootNode, f.Line, f.Column) {
				fixesCount++
				modified = true
			}

		case "CICD-SEC-10": // Insufficient Logging & Visibility - continue-on-error
			if removeMapEntry(rootNode, f.Line, f.Column) {
				fixesCount++
				modified = true
			}

		case "SLSA-BUILD-L2":
			// Multiple SLSA-L2 rules share this category; dispatch on RuleID.
			switch f.RuleID {
			case RuleSLSAOIDCTokenScope:
				if fixSLSAOIDCTokenScope(rootNode, f) {
					fixesCount++
					modified = true
				}
			case RuleSLSAPermsOverlyBroad:
				if fixSLSAPermsOverlyBroad(rootNode, f) {
					fixesCount++
					modified = true
				}
			}

		case "CICD-SEC-4": // PPE - Shell Injection
			runNode := findNodeByPosition(rootNode, f.Line, f.Column)
			if runNode != nil && runNode.Kind == yaml.ScalarNode {
				stepNode := findParentMappingNode(rootNode, runNode)
				// Only auto-fix inline run: scripts. A finding anchored on an
				// action with:-input value re-evaluates ${{ }} itself, so
				// hoisting into env: would not help and could corrupt the
				// workflow — leave those for manual remediation.
				if stepNode != nil && mapKeyForValue(stepNode, runNode) == "run" {
					matches := rePPEUntrustedCtx.FindAllString(runNode.Value, -1)
					if len(matches) > 0 {
						// Ensure 'env' mapping node exists under this step
						_, envNode, _ := findMapKey(stepNode, "env")
						if envNode == nil {
							envNode = &yaml.Node{
								Kind: yaml.MappingNode,
								Tag:  "!!map",
							}
							setMapKey(stepNode, "env", envNode)
						}

						newRunVal := runNode.Value
						for _, match := range matches {
							varName := getPPEEnvName(match)

							// Add var to env mapping if not already present
							_, varValNode, _ := findMapKey(envNode, varName)
							if varValNode == nil {
								valNode := &yaml.Node{
									Kind:  yaml.ScalarNode,
									Tag:   "!!str",
									Value: match,
								}
								setMapKey(envNode, varName, valNode)
							}

							// Replace interpolation expression with $VAR_NAME in run script
							newRunVal = strings.ReplaceAll(newRunVal, match, "$"+varName)
						}

						runNode.Value = newRunVal
						fixesCount++
						modified = true
					}
				}
			}
		}
	}

	if !modified {
		return nil, 0, nil
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		return nil, 0, fmt.Errorf("failed to encode modified YAML: %w", err)
	}
	return restoreBlankLines(buf.Bytes()), fixesCount, nil
}

// findMapKey locates a key/value node pair by key name in a mapping node.
func findMapKey(mapNode *yaml.Node, key string) (keyNode *yaml.Node, valNode *yaml.Node, index int) {
	if mapNode.Kind != yaml.MappingNode {
		return nil, nil, -1
	}
	for i := 0; i < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			return mapNode.Content[i], mapNode.Content[i+1], i
		}
	}
	return nil, nil, -1
}

// setMapKey sets or inserts a key/value node pair in a mapping node.
func setMapKey(mapNode *yaml.Node, key string, valNode *yaml.Node) {
	_, _, idx := findMapKey(mapNode, key)
	if idx != -1 {
		mapNode.Content[idx+1] = valNode
	} else {
		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: key,
		}
		mapNode.Content = append(mapNode.Content, keyNode, valNode)
	}
}

// insertMapNode prepends a key-value node pair to a mapping node.
func insertMapNode(mapNode *yaml.Node, key string, valNode *yaml.Node) {
	if mapNode.Kind != yaml.MappingNode {
		return
	}
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: key,
	}
	mapNode.Content = append([]*yaml.Node{keyNode, valNode}, mapNode.Content...)
}

// reOnlyExprGlue matches an if:-condition residue (the text outside ${{ }}
// blocks) that consists solely of boolean glue — operators, parentheses, and
// whitespace. When that holds, the blocks can be safely merged into one.
var reOnlyExprGlue = regexp.MustCompile(`^[\s()!&|]*$`)

// fixUnsoundCondition rewrites an always-truthy if: value into a single
// well-formed expression, but only when the literal text between the ${{ }}
// blocks is pure boolean glue (operators/parens/whitespace). It merges
// `${{ a }} && ${{ b }}` into `${{ a && b }}`. When the residue contains real
// words (e.g. `${{ a }} always`), the intent is ambiguous, so it leaves the
// finding for manual remediation.
func fixUnsoundCondition(ifNode *yaml.Node) bool {
	v := ifNode.Value
	blocks := reExprBlock.FindAllString(v, -1)
	if len(blocks) == 0 {
		return false
	}
	residue := reExprBlock.ReplaceAllString(v, " ")
	if !reOnlyExprGlue.MatchString(residue) {
		return false
	}
	// Substitute each block with its inner expression, preserving the glue.
	i := 0
	merged := reExprBlock.ReplaceAllStringFunc(v, func(string) string {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(blocks[i], "${{"), "}}"))
		i++
		return inner
	})
	merged = strings.Join(strings.Fields(merged), " ")
	ifNode.Value = "${{ " + merged + " }}"
	ifNode.Style = 0
	ifNode.Tag = ""
	return true
}

// fixPullRequestTarget renames pull_request_target triggers to pull_request.
func fixPullRequestTarget(onNode *yaml.Node) bool {
	if onNode.Kind == yaml.ScalarNode && onNode.Value == "pull_request_target" {
		onNode.Value = "pull_request"
		return true
	}
	if onNode.Kind == yaml.SequenceNode {
		hasPR := false
		targetIdx := -1
		for i, item := range onNode.Content {
			if item.Value == "pull_request" {
				hasPR = true
			}
			if item.Value == "pull_request_target" {
				targetIdx = i
			}
		}
		if targetIdx != -1 {
			if hasPR {
				onNode.Content = append(onNode.Content[:targetIdx], onNode.Content[targetIdx+1:]...)
			} else {
				onNode.Content[targetIdx].Value = "pull_request"
			}
			return true
		}
	}
	if onNode.Kind == yaml.MappingNode {
		hasPR := false
		targetIdx := -1
		for i := 0; i < len(onNode.Content); i += 2 {
			if onNode.Content[i].Value == "pull_request" {
				hasPR = true
			}
			if onNode.Content[i].Value == "pull_request_target" {
				targetIdx = i
			}
		}
		if targetIdx != -1 {
			if hasPR {
				onNode.Content = append(onNode.Content[:targetIdx], onNode.Content[targetIdx+2:]...)
			} else {
				onNode.Content[targetIdx].Value = "pull_request"
			}
			return true
		}
	}
	return false
}

// fixCheckoutPersistCredentials adds `persist-credentials: false` to the with:
// block of the actions/checkout step at the finding's position, creating the
// with: block if needed.
func fixCheckoutPersistCredentials(rootNode *yaml.Node, f Finding) bool {
	usesNode := findNodeByPosition(rootNode, f.Line, f.Column)
	if usesNode == nil {
		return false
	}
	stepNode := findParentMappingNode(rootNode, usesNode)
	if stepNode == nil || mapKeyForValue(stepNode, usesNode) != "uses" {
		return false
	}
	_, withNode, _ := findMapKey(stepNode, "with")
	if withNode == nil {
		withNode = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMapKey(stepNode, "with", withNode)
	}
	if withNode.Kind != yaml.MappingNode {
		return false
	}
	if _, existing, _ := findMapKey(withNode, "persist-credentials"); existing != nil {
		if strings.EqualFold(existing.Value, "false") {
			return false // already correct
		}
		existing.Value = "false"
		existing.Style = 0
		existing.Tag = ""
		return true
	}
	setMapKey(withNode, "persist-credentials", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
	return true
}

// fixUnpinnedAction resolves the tag/branch to a commit SHA and pins it.
func fixUnpinnedAction(usesNode *yaml.Node) bool {
	usesVal := usesNode.Value
	if usesVal == "" {
		return false
	}
	// Ignore local actions
	if strings.HasPrefix(usesVal, "./") || strings.HasPrefix(usesVal, ".github/") {
		return false
	}
	parts := strings.Split(usesVal, "@")
	if len(parts) != 2 {
		return false
	}
	ref := parts[1]
	reSHA := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	if reSHA.MatchString(ref) {
		return false // Already pinned
	}

	// Resolve commit SHA from GitHub API
	sha, err := resolveTagToSHA(usesVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not resolve commit SHA for action %q: %v\n", usesVal, err)
		return false
	}

	usesNode.Value = fmt.Sprintf("%s@%s", parts[0], sha)
	// yaml.v3 prefixes line comments with "# "; pass the bare ref so the result
	// is "# v4" rather than "#  v4".
	usesNode.LineComment = ref
	return true
}

var githubAPIBaseURL = "https://api.github.com"

// resolveTagToSHA fetches the commit SHA for a given ref from the GitHub API.
func resolveTagToSHA(actionRef string) (string, error) {
	parts := strings.Split(actionRef, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid action reference")
	}
	repoPart := parts[0]
	ref := parts[1]

	repoParts := strings.Split(repoPart, "/")
	if len(repoParts) < 2 {
		return "", fmt.Errorf("invalid repository format")
	}
	owner := repoParts[0]
	repo := repoParts[1]

	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", githubAPIBaseURL, owner, repo, ref)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "pipefort-fixer")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status: %s", resp.Status)
	}

	var result struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.SHA) != 40 {
		return "", fmt.Errorf("invalid commit SHA from GitHub: %q", result.SHA)
	}

	return result.SHA, nil
}

// findNodeByPosition recursively finds a node matching a line and column.
func findNodeByPosition(node *yaml.Node, line, col int) *yaml.Node {
	if node.Line == line && node.Column == col {
		return node
	}
	for _, child := range node.Content {
		if found := findNodeByPosition(child, line, col); found != nil {
			return found
		}
	}
	return nil
}

// mapKeyForValue returns the key string under which valNode sits in mapNode, or
// "" if valNode is not a value in mapNode. Used to confirm a finding's anchor
// node is the value of the expected key (e.g. "run") before fixing it.
func mapKeyForValue(mapNode *yaml.Node, valNode *yaml.Node) string {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return ""
	}
	for i := 1; i < len(mapNode.Content); i += 2 {
		if mapNode.Content[i] == valNode {
			return mapNode.Content[i-1].Value
		}
	}
	return ""
}

// findParentMappingNode recursively searches for the mapping node containing a child node.
func findParentMappingNode(current *yaml.Node, target *yaml.Node) *yaml.Node {
	if current.Kind == yaml.MappingNode {
		for _, child := range current.Content {
			if child == target {
				return current
			}
		}
	}
	for _, child := range current.Content {
		if parent := findParentMappingNode(child, target); parent != nil {
			return parent
		}
	}
	return nil
}

// hardcodedSecretFixPatterns mirrors the typed regexes in CheckHardcodedSecrets,
// minus the "Generic Token" pattern. Generic Token matches an enclosing
// `token := "..."` shape rather than just the literal, so a blind substitution
// would corrupt the surrounding syntax — it's left for manual review.
//
// The envName fields are the canonical env-var name the fixer hoists into.
// Users still need to add the corresponding repo secret in GitHub; the fix
// gets the workflow shape right so the scanner stops flagging it.
var hardcodedSecretFixPatterns = []struct {
	envName string
	re      *regexp.Regexp
}{
	{"GH_TOKEN", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"SLACK_TOKEN", regexp.MustCompile(`\bxoxb-[0-9]{11,13}-[A-Za-z0-9]{24}\b`)},
	{"AWS_ACCESS_KEY_ID", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
}

// fixHardcodedSecretInRun replaces every typed secret literal inside the
// step's run-script scalar with a $ENV_NAME reference and ensures the step's
// env block defines that name as a secrets-context expression. Returns true
// if any literal was hoisted.
//
// stepMap is the parent mapping node of runNode — i.e. the step itself.
func fixHardcodedSecretInRun(runNode *yaml.Node, stepMap *yaml.Node) bool {
	newRunVal := runNode.Value
	modified := false

	for _, p := range hardcodedSecretFixPatterns {
		if !p.re.MatchString(newRunVal) {
			continue
		}
		// ReplaceAllLiteralString — not ReplaceAllString — because the
		// replacement contains a literal "$" that regexp.ReplaceAllString
		// would otherwise treat as a capture-group reference and strip.
		newRunVal = p.re.ReplaceAllLiteralString(newRunVal, "$"+p.envName)

		_, envNode, _ := findMapKey(stepMap, "env")
		if envNode == nil {
			envNode = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			setMapKey(stepMap, "env", envNode)
		}
		if _, existing, _ := findMapKey(envNode, p.envName); existing == nil {
			setMapKey(envNode, p.envName, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: fmt.Sprintf("${{ secrets.%s }}", p.envName),
			})
		}
		modified = true
	}

	if modified {
		runNode.Value = newRunVal
		// Keep the original Style/Tag so a literal-block ("|") run script
		// stays a literal block after rewrite, instead of collapsing into a
		// double-quoted one-liner with embedded \n escapes.
	}
	return modified
}

// removeMapEntry removes the key/value pair whose value node sits at the given
// line/column. Used by category fixers that only need to delete a leaf entry
// (e.g. CICD-SEC-7 removes a debug-logging env var; CICD-SEC-10 removes a
// job-level continue-on-error: true).
func removeMapEntry(rootNode *yaml.Node, line, col int) bool {
	valNode := findNodeByPosition(rootNode, line, col)
	if valNode == nil {
		return false
	}
	parent := findParentMappingNode(rootNode, valNode)
	if parent == nil {
		return false
	}
	for i := 1; i < len(parent.Content); i += 2 {
		if parent.Content[i] == valNode {
			parent.Content = append(parent.Content[:i-1], parent.Content[i+1:]...)
			return true
		}
	}
	return false
}

// findJobContainingLine returns the job mapping whose subtree contains the
// given line. SLSA fixers need this when the finding's position is on a step
// (uses/run) inside a job and the fix has to touch the job's permissions
// block higher up.
func findJobContainingLine(rootNode *yaml.Node, line int) *yaml.Node {
	_, jobsNode, _ := findMapKey(rootNode, "jobs")
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		valNode := jobsNode.Content[i+1]
		if subtreeContainsLine(valNode, line) {
			return valNode
		}
	}
	return nil
}

func subtreeContainsLine(node *yaml.Node, line int) bool {
	if node == nil {
		return false
	}
	if node.Line == line {
		return true
	}
	for _, child := range node.Content {
		if subtreeContainsLine(child, line) {
			return true
		}
	}
	return false
}

// fixSLSAOIDCTokenScope adds id-token: write to the offending job's
// permissions block, creating the block (with a safe contents: read default)
// if missing. The check already accounts for workflow-level grants — if we're
// called, the job genuinely needs its own.
func fixSLSAOIDCTokenScope(rootNode *yaml.Node, f Finding) bool {
	jobMap := findJobContainingLine(rootNode, f.Line)
	if jobMap == nil || jobMap.Kind != yaml.MappingNode {
		return false
	}
	_, permNode, idx := findMapKey(jobMap, "permissions")
	if permNode == nil {
		setMapKey(jobMap, "permissions", newPermissionsMap("contents", "read", "id-token", "write"))
		return true
	}
	if permNode.Kind == yaml.ScalarNode {
		// A scalar like read-all (or write-all — covered by the overly-broad
		// rule) can't carry id-token: write. Replace with the minimum the
		// signing job actually needs; the user keeps explicit control via the
		// resulting mapping.
		jobMap.Content[idx+1] = newPermissionsMap("contents", "read", "id-token", "write")
		return true
	}
	if permNode.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(permNode.Content); i += 2 {
			if strings.EqualFold(permNode.Content[i].Value, "id-token") {
				if strings.EqualFold(permNode.Content[i+1].Value, "write") {
					return false // already correct
				}
				permNode.Content[i+1].Value = "write"
				permNode.Content[i+1].Style = 0
				permNode.Content[i+1].Tag = ""
				return true
			}
		}
		permNode.Content = append(permNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "id-token"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "write"},
		)
		return true
	}
	return false
}

// newPermissionsMap builds a yaml.MappingNode from alternating key/value strings.
func newPermissionsMap(kv ...string) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(kv); i += 2 {
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv[i]},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv[i+1]},
		)
	}
	return m
}

// fixSLSAPermsOverlyBroad replaces a scalar write-all permissions block with
// read-all. The mapping form (≥4 explicit writes) is left for manual review —
// some of those scopes may have been deliberately chosen.
func fixSLSAPermsOverlyBroad(rootNode *yaml.Node, f Finding) bool {
	permNode := findNodeByPosition(rootNode, f.Line, f.Column)
	if permNode == nil || permNode.Kind != yaml.ScalarNode {
		return false
	}
	if !strings.EqualFold(permNode.Value, "write-all") {
		return false
	}
	permNode.Value = "read-all"
	permNode.Style = 0
	permNode.Tag = ""
	return true
}

// getPPEEnvName sanitizes and converts a event context expression to an uppercase environment variable name.
func getPPEEnvName(expr string) string {
	clean := strings.TrimSpace(expr)
	clean = strings.TrimPrefix(clean, "${{")
	clean = strings.TrimSuffix(clean, "}}")
	clean = strings.TrimSpace(clean)
	clean = strings.TrimPrefix(clean, "github.event.")

	if strings.HasPrefix(clean, "pull_request.") {
		suffix := strings.TrimPrefix(clean, "pull_request.")
		suffix = strings.ReplaceAll(suffix, ".", "_")
		return "PR_" + strings.ToUpper(suffix)
	}
	if strings.HasPrefix(clean, "issue.") {
		suffix := strings.TrimPrefix(clean, "issue.")
		suffix = strings.ReplaceAll(suffix, ".", "_")
		return "ISSUE_" + strings.ToUpper(suffix)
	}

	// Replace all non-alphanumeric characters with underscores
	reg := regexp.MustCompile(`[^a-zA-Z0-9]`)
	clean = reg.ReplaceAllString(clean, "_")
	// Clean up consecutive underscores
	for strings.Contains(clean, "__") {
		clean = strings.ReplaceAll(clean, "__", "_")
	}
	clean = strings.Trim(clean, "_")

	return strings.ToUpper(clean)
}
