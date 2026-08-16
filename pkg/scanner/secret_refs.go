package scanner

import (
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Where a workflow reads a secret.
//
// The rules already recognise secret references, but only as evidence for a
// finding — "this run: line prints a secret". Nothing exported the plain fact
// that a workflow reads a given secret, so a consumer holding an inventory of
// organisation secrets could not answer the first question anyone asks about
// one: who uses this, and can I rotate it?
//
// This is extraction, not detection. It produces no findings and makes no
// judgement; a reference here is normal and expected. The judgement belongs to
// whoever joins it against something else — an inventory, or the findings for
// the same file.

// SecretRefKind separates a reference naming one secret from one that reaches
// all of them.
//
// The distinction is load-bearing. `${{ toJSON(secrets) }}`, `secrets[key]`
// and `secrets: inherit` do not name anything, yet each hands over EVERY
// secret in scope. A consumer that only collected named references would
// report "nothing reads DEPLOY_KEY" about a workflow that reads all of them,
// which is the most dangerous sentence this data could produce.
type SecretRefKind string

const (
	// SecretRefNamed is `${{ secrets.NAME }}` — one identified secret.
	SecretRefNamed SecretRefKind = "named"
	// SecretRefAll is a whole-context read: toJSON(secrets) or secrets[expr].
	// Name is empty.
	SecretRefAll SecretRefKind = "all"
	// SecretRefInherit is `secrets: inherit` on a reusable-workflow call: the
	// called workflow receives every secret the caller can see. Name is empty
	// and Target carries the called workflow.
	SecretRefInherit SecretRefKind = "inherit"
)

// SecretRef is one place a workflow reads a secret.
type SecretRef struct {
	Kind SecretRefKind `json:"kind"`
	// Name is the secret's name for SecretRefNamed, empty otherwise. Compared
	// case-sensitively: GitHub secret names are upper-cased on creation and the
	// expression context matches them exactly.
	Name string `json:"name,omitempty"`
	File string `json:"file"`
	Line int    `json:"line"`
	// Job is the job id the reference sits in, empty for workflow-level
	// (top-level env, or `on.workflow_call` declarations).
	Job string `json:"job,omitempty"`
	// Target is the called workflow for SecretRefInherit, empty otherwise.
	Target string `json:"target,omitempty"`
}

var (
	// secretNamedRe captures `${{ secrets.NAME }}`. Kept separate from the
	// rules' own patterns so tightening a rule cannot silently change what the
	// inventory reports.
	secretNamedRe = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)
	// secretBareRe catches `secrets.NAME` outside a ${{ }} block, which is how
	// it appears inside `if:` conditions.
	secretBareRe = regexp.MustCompile(`\bsecrets\.([A-Za-z_][A-Za-z0-9_-]*)\b`)
	// secretAllRe matches the whole-context reads that name nothing.
	secretAllRe = regexp.MustCompile(`(?i)(toJSON\(\s*secrets\s*\)|\bsecrets\s*\[)`)
)

// SecretReferences returns every secret read in one workflow file, in file
// order. It returns nil for a file it cannot parse or that is not a workflow —
// silence rather than an error, matching ScanBytes, because a caller sweeping a
// repository should not have one odd file end the sweep.
//
// GITHUB_TOKEN is excluded: it is minted per run rather than stored, so it
// never appears in a secrets inventory and listing it would add a row nobody
// can rotate.
func SecretReferences(file string, content []byte) []SecretRef {
	var workflow WorkflowNode
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil
	}
	if workflow.Jobs.Kind == 0 && workflow.On.Kind == 0 {
		return nil
	}

	var out []SecretRef
	// Workflow-level env, and anything else above the jobs mapping.
	out = append(out, secretRefsInNode(file, "", &workflow.Env)...)

	if workflow.Jobs.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(workflow.Jobs.Content); i += 2 {
			jobID := workflow.Jobs.Content[i].Value
			jobNode := workflow.Jobs.Content[i+1]
			out = append(out, secretRefsInNode(file, jobID, jobNode)...)
			out = append(out, inheritRefsInJob(file, jobID, jobNode)...)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// secretRefsInNode walks every scalar under node, so a reference is found
// wherever it sits — env, with, run, if, a matrix entry — without this having
// to enumerate the workflow schema. Enumerating it is how you end up missing
// the one field an attacker used.
func secretRefsInNode(file, job string, node *yaml.Node) []SecretRef {
	if node == nil {
		return nil
	}
	var out []SecretRef
	if node.Kind == yaml.ScalarNode {
		return secretRefsInString(file, job, node.Value, node.Line)
	}
	for _, child := range node.Content {
		out = append(out, secretRefsInNode(file, job, child)...)
	}
	return out
}

func secretRefsInString(file, job, value string, line int) []SecretRef {
	if value == "" {
		return nil
	}
	var out []SecretRef
	seen := map[string]bool{}

	add := func(kind SecretRefKind, name string) {
		key := string(kind) + "\x00" + name
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, SecretRef{Kind: kind, Name: name, File: file, Line: line, Job: job})
	}

	for _, m := range secretNamedRe.FindAllStringSubmatch(value, -1) {
		if isGitHubToken(m[1]) {
			continue
		}
		add(SecretRefNamed, m[1])
	}
	// `if:` conditions carry bare `secrets.NAME`. Run it too — the dedup above
	// keeps a name found both ways from being counted twice.
	for _, m := range secretBareRe.FindAllStringSubmatch(value, -1) {
		if isGitHubToken(m[1]) {
			continue
		}
		add(SecretRefNamed, m[1])
	}
	if secretAllRe.MatchString(value) {
		add(SecretRefAll, "")
	}
	return out
}

// inheritRefsInJob finds `secrets: inherit` on a reusable-workflow call.
//
// It is looked for structurally rather than textually because "inherit" is an
// ordinary word: a scalar walk would match it in a step name or a comment-like
// string. Only the job-level `secrets:` key means what this reports.
func inheritRefsInJob(file, job string, jobNode *yaml.Node) []SecretRef {
	if jobNode == nil || jobNode.Kind != yaml.MappingNode {
		return nil
	}
	var target string
	var ref *SecretRef
	for i := 0; i+1 < len(jobNode.Content); i += 2 {
		key := jobNode.Content[i]
		val := jobNode.Content[i+1]
		switch key.Value {
		case "uses":
			if val.Kind == yaml.ScalarNode {
				target = val.Value
			}
		case "secrets":
			if val.Kind == yaml.ScalarNode && val.Value == "inherit" {
				ref = &SecretRef{Kind: SecretRefInherit, File: file, Line: val.Line, Job: job}
			}
		}
	}
	if ref == nil {
		return nil
	}
	ref.Target = target
	return []SecretRef{*ref}
}

// isGitHubToken excludes the per-run token. It is minted by GitHub rather than
// stored, so it never appears in a secrets inventory, and listing it would add
// a row nobody can rotate.
func isGitHubToken(name string) bool {
	return strings.EqualFold(name, "GITHUB_TOKEN")
}

// SecretNamesRead returns the distinct named secrets read in a file, sorted.
// Convenience for the common "which of my inventory does this workflow touch"
// join; callers still have to handle SecretRefAll and SecretRefInherit, which
// name nothing and reach everything.
func SecretNamesRead(refs []SecretRef) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range refs {
		if r.Kind != SecretRefNamed || r.Name == "" || seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// ReadsEverySecret reports whether any reference hands over the whole secrets
// context. When true, "which secrets does this workflow read" has the answer
// "all of them", regardless of what SecretNamesRead returned.
func ReadsEverySecret(refs []SecretRef) bool {
	for _, r := range refs {
		if r.Kind == SecretRefAll || r.Kind == SecretRefInherit {
			return true
		}
	}
	return false
}
