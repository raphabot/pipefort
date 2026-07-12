package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file holds the offline rule-parity batch that closes the gap against
// zizmor's audit set: unsound conditions, obfuscation, cache poisoning in
// publishing workflows, over-provisioned secrets, trusted-publishing nudges,
// and missing concurrency guards. Each Check* is wired into ScanBytes.

var (
	// reExprBlock matches one ${{ ... }} expression block.
	reExprBlock = regexp.MustCompile(`\$\{\{[^}]*\}\}`)
	// reUnsoundContains matches contains('literal', github.<ctx>) — a string
	// haystack tested for an attacker-influenceable needle.
	reUnsoundContains = regexp.MustCompile(`(?i)contains\(\s*'[^']*'\s*,\s*(github|inputs|env)\.`)
	// reIndexContext matches obfuscated index-notation context access, e.g.
	// github['event']['issue'] instead of github.event.issue.
	reIndexContext = regexp.MustCompile(`(?i)\b(github|env|secrets|inputs|steps|needs)\s*\[\s*['"]`)
	// reBase64Exec matches decode-and-execute chains in run scripts.
	reBase64Exec = regexp.MustCompile(`(?i)(base64\s+(-d|--decode|-D)|certutil\s+-decode|[^|]*\|\s*base64\s+(-d|--decode))[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex|powershell)\b`)
	// reToJSONSecrets matches ${{ toJSON(secrets) }} exposure.
	reToJSONSecrets = regexp.MustCompile(`(?i)toJSON\(\s*secrets\s*\)`)
	// reSecretsRef matches a secrets.<NAME> reference (for over-provisioned
	// workflow-level env detection).
	reSecretsRef = regexp.MustCompile(`(?i)\bsecrets\.[A-Za-z_][A-Za-z0-9_-]*`)
)

// --- CheckUnsoundCondition --------------------------------------------------

// CheckUnsoundCondition flags job/step `if:` values that GitHub evaluates to a
// constant-truthy string rather than a boolean. The canonical bug is mixing
// literal text with an expression — either multiple ${{ }} blocks joined by
// literal operators, or literal text outside a single ${{ }} block. GitHub then
// treats the whole value as a non-empty string, which is always truthy, so the
// guard never actually gates.
func CheckUnsoundCondition(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	report := func(node yaml.Node, where string) {
		if node.Value == "" {
			return
		}
		if unsoundIfExpression(node.Value) {
			findings = append(findings, Finding{
				File:     file,
				Line:     node.Line,
				Column:   node.Column,
				Severity: SeverityHigh,
				Category: "CICD-SEC-1",
				RuleID:   RuleUnsoundCondition,
				Title:    "Job/step condition is always true",
				Description: fmt.Sprintf(
					"The if: condition on %s mixes literal text with GitHub expression blocks, so it is evaluated as a non-empty string (always truthy) instead of a boolean. The guard it appears to enforce never gates.",
					where,
				),
				Recommendation: "Wrap the entire condition in a single ${{ ... }} block (e.g. `if: ${{ a == 'x' && b == 'y' }}`) so it evaluates as one boolean expression.",
			})
		}
	}

	for _, j := range jobs {
		report(j.Node.If, fmt.Sprintf("job %q", j.ID))
		for _, s := range decodeSteps(j.Node) {
			report(s.If, fmt.Sprintf("a step in job %q", j.ID))
		}
	}
	return findings
}

// unsoundIfExpression reports whether an if: value would be evaluated as a
// constant-truthy string. True when there is a ${{ }} block AND non-whitespace
// characters exist outside the block(s) — literal text turns the value into a
// string concatenation.
func unsoundIfExpression(v string) bool {
	blocks := reExprBlock.FindAllString(v, -1)
	if len(blocks) == 0 {
		return false // bare expression form (no ${{ }}) is evaluated correctly
	}
	outside := reExprBlock.ReplaceAllString(v, "")
	return strings.TrimSpace(outside) != ""
}

// --- CheckUnsoundContains ---------------------------------------------------

// CheckUnsoundContains flags contains('literal haystack', <context>) where the
// needle is attacker-influenceable (a ref, label, title, …). A crafted value
// that is a substring of the haystack satisfies the check and passes the gate.
func CheckUnsoundContains(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding
	seen := map[int]bool{}

	scan := func(node yaml.Node, where string) {
		if node.Value == "" || seen[node.Line] {
			return
		}
		if reUnsoundContains.MatchString(node.Value) {
			seen[node.Line] = true
			findings = append(findings, Finding{
				File:     file,
				Line:     node.Line,
				Column:   node.Column,
				Severity: SeverityMedium,
				Category: "CICD-SEC-1",
				RuleID:   RuleUnsoundContains,
				Title:    "Spoofable contains() membership check",
				Description: fmt.Sprintf(
					"%s uses contains() with a literal string haystack and a context needle. An attacker who controls the needle (branch ref, PR label/title, …) can craft a substring that satisfies the check.",
					where,
				),
				Recommendation: "Compare against an exact list instead of a substring: use `contains(fromJSON('[\"a\",\"b\"]'), needle)` (array membership) or an explicit `needle == 'a' || needle == 'b'`.",
			})
		}
	}

	for _, j := range jobs {
		scan(j.Node.If, fmt.Sprintf("The if: on job %q", j.ID))
		for _, s := range decodeSteps(j.Node) {
			scan(s.If, fmt.Sprintf("A step in job %q", j.ID))
		}
	}
	return findings
}

// --- CheckObfuscatedExpression ----------------------------------------------

// CheckObfuscatedExpression flags obfuscation that hides untrusted-input flow
// from human review: index-notation context access and base64-decode-and-run
// chains in run scripts.
func CheckObfuscatedExpression(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, j := range jobs {
		for _, s := range decodeSteps(j.Node) {
			if s.Run.Value != "" && reBase64Exec.MatchString(s.Run.Value) {
				findings = append(findings, Finding{
					File:     file,
					Line:     s.Run.Line,
					Column:   s.Run.Column,
					Severity: SeverityMedium,
					Category: "CICD-SEC-4",
					RuleID:   RuleObfuscatedExpr,
					Title:    "Obfuscated run script (decode-and-execute)",
					Description: fmt.Sprintf(
						"A step in job %q decodes content (base64/certutil) and pipes it straight to a shell. This obfuscates what actually runs and is a common way to smuggle untrusted code past review.",
						j.ID,
					),
					Recommendation: "Run the decoded content from a committed, reviewable file instead of decoding-and-executing inline, or drop the indirection entirely.",
				})
			}
			// Index-notation context access in run scripts, with:, and env:.
			for _, node := range []yaml.Node{s.Run, s.With, s.Env} {
				if reIndexContext.MatchString(nodeText(&node)) {
					findings = append(findings, Finding{
						File:     file,
						Line:     obfLine(node),
						Column:   obfCol(node),
						Severity: SeverityMedium,
						Category: "CICD-SEC-4",
						RuleID:   RuleObfuscatedExpr,
						Title:    "Obfuscated context access (index notation)",
						Description: fmt.Sprintf(
							"A step in job %q accesses a context with index notation (e.g. github['event']['…']) instead of dotted access. This obscures untrusted-input flow and defeats pattern-based review.",
							j.ID,
						),
						Recommendation: "Use dotted context access (github.event.…) so injection sinks are visible to reviewers and scanners.",
					})
					break // one obfuscation finding per step is enough
				}
			}
		}
	}
	return findings
}

// --- CheckCachePoisoningRelease ---------------------------------------------

// cacheActionPrefixes are actions whose sole/primary purpose is restoring a
// build cache.
var cacheActionPrefixes = []string{"actions/cache"}

// CheckCachePoisoningRelease flags dependency caching inside a workflow that
// also publishes a release-shaped artifact. A cache entry poisoned by a
// lower-trust workflow (e.g. one triggered by a fork PR) can be restored here
// and flow into the published output.
func CheckCachePoisoningRelease(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	publishes, _, _ := workflowPublishes(workflow, jobs)
	if !publishes {
		return nil
	}

	var findings []Finding
	for _, j := range jobs {
		for _, s := range decodeSteps(j.Node) {
			isCache := stepUsesAny(s, cacheActionPrefixes...)
			// setup-* actions with a `cache:` input also restore caches.
			if !isCache && strings.Contains(s.Uses.Value, "actions/setup-") && strings.Contains(strings.ToLower(nodeText(&s.With)), "cache") {
				isCache = true
			}
			if isCache {
				findings = append(findings, Finding{
					File:     file,
					Line:     s.Uses.Line,
					Column:   s.Uses.Column,
					Severity: SeverityMedium,
					Category: "CICD-SEC-4",
					RuleID:   RuleCachePoisonRelease,
					Title:    "Caching enabled in a publishing workflow",
					Description: fmt.Sprintf(
						"Job %q restores a build cache in a workflow that publishes a release-shaped artifact. A cache entry poisoned by a lower-trust workflow can be restored here and end up in the published output.",
						j.ID,
					),
					Recommendation: "Disable cache writes on the publishing path (e.g. `lookup-only: true` on actions/cache, or drop the setup action's cache: option) so a release build never restores a mutable cache.",
				})
			}
		}
	}
	return findings
}

// --- CheckOverprovisionedSecrets --------------------------------------------

// CheckOverprovisionedSecrets flags two over-exposure patterns: toJSON(secrets)
// (dumps every secret at once) and workflow-level env: mapping of secrets.*
// (leaks the secret into every step of every job).
func CheckOverprovisionedSecrets(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	// Workflow-level env referencing secrets — visible to every step.
	if workflow.Env.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(workflow.Env.Content); i += 2 {
			val := workflow.Env.Content[i+1]
			if reSecretsRef.MatchString(val.Value) {
				findings = append(findings, Finding{
					File:     file,
					Line:     workflow.Env.Content[i].Line,
					Column:   workflow.Env.Content[i].Column,
					Severity: SeverityMedium,
					Category: "CICD-SEC-6",
					RuleID:   RuleOverprovSecrets,
					Title:    "Secret exposed at workflow-level env",
					Description: fmt.Sprintf(
						"Workflow-level env var %q is bound to a secret, so every step of every job can read it — far wider than the one step that needs it.",
						workflow.Env.Content[i].Value,
					),
					Recommendation: "Move the secret binding down to the specific step's env: block so it is only present where it's used.",
				})
			}
		}
	}

	// toJSON(secrets) anywhere in run scripts / with / env values.
	for _, j := range jobs {
		for _, s := range decodeSteps(j.Node) {
			for _, node := range []yaml.Node{s.Run, s.With, s.Env, s.If} {
				if reToJSONSecrets.MatchString(nodeText(&node)) {
					findings = append(findings, Finding{
						File:     file,
						Line:     obfLine(node),
						Column:   obfCol(node),
						Severity: SeverityHigh,
						Category: "CICD-SEC-6",
						RuleID:   RuleOverprovSecrets,
						Title:    "All secrets exposed via toJSON(secrets)",
						Description: fmt.Sprintf(
							"A step in job %q references toJSON(secrets), which serializes every repository/organization secret into one value — a single injection or log leak exposes the entire secret store.",
							j.ID,
						),
						Recommendation: "Reference only the specific secrets you need (secrets.NAME) instead of the whole secrets context.",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- CheckUseTrustedPublishing ----------------------------------------------

// CheckUseTrustedPublishing nudges publishing steps that use a long-lived
// registry token toward OIDC trusted publishing (short-lived, per-run
// credentials). Currently targets PyPI (the most mature trusted-publishing
// ecosystem) plus token-based npm/cargo/rubygems publishes.
func CheckUseTrustedPublishing(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, j := range jobs {
		for _, s := range decodeSteps(j.Node) {
			// PyPI: pypa/gh-action-pypi-publish with an explicit password input
			// (OIDC trusted publishing needs no password).
			if stepUsesAny(s, "pypa/gh-action-pypi-publish") && strings.Contains(strings.ToLower(nodeText(&s.With)), "password") {
				findings = append(findings, publishFinding(file, s.Uses.Line, s.Uses.Column, j.ID, "PyPI", "Remove the password: input and configure OIDC trusted publishing on PyPI (https://docs.pypi.org/trusted-publishers/)."))
				continue
			}
			if s.Run.Value == "" {
				continue
			}
			env := strings.ToLower(nodeText(&s.Env))
			switch {
			case strings.Contains(s.Run.Value, "npm publish") && strings.Contains(env, "node_auth_token"):
				findings = append(findings, publishFinding(file, s.Run.Line, s.Run.Column, j.ID, "npm", "Use npm's OIDC trusted publishing (`--provenance` with an id-token) instead of a long-lived NODE_AUTH_TOKEN."))
			case strings.Contains(s.Run.Value, "cargo publish") && strings.Contains(env, "cargo_registry_token"):
				findings = append(findings, publishFinding(file, s.Run.Line, s.Run.Column, j.ID, "crates.io", "Prefer crates.io trusted publishing over a standing CARGO_REGISTRY_TOKEN."))
			case strings.Contains(s.Run.Value, "gem push") && strings.Contains(env, "gem_host_api_key"):
				findings = append(findings, publishFinding(file, s.Run.Line, s.Run.Column, j.ID, "RubyGems", "Use RubyGems OIDC trusted publishing instead of a long-lived GEM_HOST_API_KEY."))
			}
		}
	}
	return findings
}

func publishFinding(file string, line, col int, jobID, registry, rec string) Finding {
	return Finding{
		File:     file,
		Line:     line,
		Column:   col,
		Severity: SeverityMedium,
		Category: "CICD-SEC-2",
		RuleID:   RuleUseTrustedPublish,
		Title:    "Package published with a long-lived token instead of OIDC",
		Description: fmt.Sprintf(
			"Job %q publishes to %s using a long-lived registry token. %s supports OIDC trusted publishing, which mints short-lived per-run credentials and removes the standing secret.",
			jobID, registry, registry,
		),
		Recommendation: rec,
	}
}

// --- CheckMissingConcurrency ------------------------------------------------

// CheckMissingConcurrency flags deploy/release-shaped workflows that lack any
// concurrency: guard (workflow-level or on every job). Overlapping runs of such
// a workflow race on shared caches, artifacts, and deploy targets.
func CheckMissingConcurrency(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	deployish, line, col := workflowPublishes(workflow, jobs)
	if !deployish {
		// Also treat any job with an `environment:` (a GitHub deployment) as
		// deploy-shaped.
		if l, c, ok := anyJobHasEnvironment(workflow); ok {
			deployish, line, col = true, l, c
		}
	}
	if !deployish {
		return nil
	}
	if workflow.Concurrency.Kind != 0 {
		return nil
	}
	// Workflow-level guard absent — accept per-job guards only if every job has
	// one (a partial guard still allows overlap on the unguarded jobs).
	allJobsGuarded := len(jobs) > 0
	for _, j := range jobs {
		if j.Node.Concurrency.Kind == 0 {
			allJobsGuarded = false
			break
		}
	}
	if allJobsGuarded {
		return nil
	}

	if line == 0 {
		line, col = 1, 1
	}
	return []Finding{{
		File:     file,
		Line:     line,
		Column:   col,
		Severity: SeverityLow,
		Category: "BEST-PRAC-4",
		RuleID:   RuleMissingConcurrency,
		Title:    "Deploy/release workflow has no concurrency guard",
		Description: "This workflow publishes or deploys but declares no concurrency: group. Two runs that overlap (e.g. rapid pushes) can race on shared caches, artifacts, and the deploy target, producing double-deploys or inconsistent state.",
		Recommendation: "Add a top-level `concurrency:` block, e.g. `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }`.",
	}}
}

// anyJobHasEnvironment reports the location of the first job declaring an
// `environment:` key (a deployment). JobNode has no environment field, so the
// raw jobs mapping is walked.
func anyJobHasEnvironment(workflow *WorkflowNode) (int, int, bool) {
	if workflow.Jobs.Kind != yaml.MappingNode {
		return 0, 0, false
	}
	for i := 1; i < len(workflow.Jobs.Content); i += 2 {
		job := workflow.Jobs.Content[i]
		if job.Kind != yaml.MappingNode {
			continue
		}
		for k := 0; k+1 < len(job.Content); k += 2 {
			if job.Content[k].Value == "environment" {
				return workflow.Jobs.Content[i-1].Line, workflow.Jobs.Content[i-1].Column, true
			}
		}
	}
	return 0, 0, false
}

// decodeSteps returns a job's steps, or nil if it has none / fails to decode.
// Small shared helper mirroring the inline decode used across rule files.
func decodeSteps(job JobNode) []StepNode {
	if job.Steps.Kind != yaml.SequenceNode {
		return nil
	}
	var steps []StepNode
	if err := job.Steps.Decode(&steps); err != nil {
		return nil
	}
	return steps
}

// obfLine/obfCol return a node's own position, falling back to its first
// child's when the node is a mapping/sequence (whose own Line points at the
// key, which is what we want anyway).
func obfLine(node yaml.Node) int {
	if node.Line > 0 {
		return node.Line
	}
	if len(node.Content) > 0 {
		return node.Content[0].Line
	}
	return 0
}

func obfCol(node yaml.Node) int {
	if node.Column > 0 {
		return node.Column
	}
	if len(node.Content) > 0 {
		return node.Content[0].Column
	}
	return 0
}

