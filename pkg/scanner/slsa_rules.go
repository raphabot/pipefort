package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SLSA Build-track workflow checks. Each Check* function mirrors the shape used
// in rules.go: takes (file, workflow, jobs), returns []Finding. They are
// appended after the OWASP/best-practice checks in scanner.go's ScanBytes.
//
// Heuristics in this file lean conservative — we'd rather miss an edge case
// than fire a noisy false positive that pushes users to disable SLSA mode.

// --- Helpers ----------------------------------------------------------------

// usesPrefixes reports whether a step's `uses:` value matches any of the given
// "owner/name" prefixes (matching is performed on the part before "@"). This
// keeps the call sites readable when we look for action families.
func stepUsesAny(step StepNode, prefixes ...string) bool {
	v := step.Uses.Value
	if v == "" {
		return false
	}
	owner := v
	if idx := strings.Index(v, "@"); idx >= 0 {
		owner = v[:idx]
	}
	for _, p := range prefixes {
		if owner == p || strings.HasPrefix(owner, p+"/") {
			return true
		}
	}
	return false
}

// jobUsesReusable reports whether a job declares `uses:` at the job level
// (i.e. it calls a reusable workflow) and the call matches one of the given
// prefixes. JobNode currently has no `uses:` field, so we re-decode the raw
// mapping out of the workflow node — see WorkflowNode.Jobs in types.go.
func jobUsesReusable(jobNode *yaml.Node, prefixes ...string) (string, bool) {
	if jobNode == nil || jobNode.Kind != yaml.MappingNode {
		return "", false
	}
	for i := 0; i+1 < len(jobNode.Content); i += 2 {
		if jobNode.Content[i].Value != "uses" {
			continue
		}
		v := jobNode.Content[i+1].Value
		ref := v
		if idx := strings.Index(v, "@"); idx >= 0 {
			ref = v[:idx]
		}
		for _, p := range prefixes {
			if strings.HasPrefix(ref, p) {
				return v, true
			}
		}
		return v, false
	}
	return "", false
}

// jobsRawForReusable returns the raw yaml mapping nodes per job ID so the
// caller can introspect job-level fields (like `uses:`) that aren't on JobNode.
func jobsRawForReusable(workflow *WorkflowNode) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	if workflow.Jobs.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(workflow.Jobs.Content); i += 2 {
		out[workflow.Jobs.Content[i].Value] = workflow.Jobs.Content[i+1]
	}
	return out
}

// jobIDToPermissions returns each job's permissions node (or nil) keyed by ID.
func jobIDToPermissions(jobs []JobNodeWithID) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	for _, j := range jobs {
		jb := j
		if jb.Node.Permissions.Kind == 0 {
			out[jb.ID] = nil
		} else {
			out[jb.ID] = &jb.Node.Permissions
		}
	}
	return out
}

// hasIDTokenWrite reports whether a permissions yaml.Node (workflow or job
// level) explicitly grants id-token: write.
func hasIDTokenWrite(perm *yaml.Node) bool {
	if perm == nil || perm.Kind == 0 {
		return false
	}
	if perm.Kind == yaml.ScalarNode {
		return strings.EqualFold(perm.Value, "write-all")
	}
	if perm.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(perm.Content); i += 2 {
		if strings.EqualFold(perm.Content[i].Value, "id-token") {
			return strings.EqualFold(perm.Content[i+1].Value, "write")
		}
	}
	return false
}

// onTriggers reports whether the workflow's `on:` block includes any of the
// given event names.
func onTriggers(workflow *WorkflowNode, names ...string) bool {
	on := workflow.On
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return want[on.Value]
	case yaml.SequenceNode:
		for _, it := range on.Content {
			if want[it.Value] {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			if want[on.Content[i].Value] {
				return true
			}
		}
	}
	return false
}

// --- Pattern constants ------------------------------------------------------

// Action prefixes used by build-provenance/signing tooling.
var (
	provenanceActionPrefixes = []string{
		"actions/attest-build-provenance",
		"actions/attest",
	}
	signingActionPrefixes = []string{
		"actions/attest-build-provenance",
		"actions/attest",
		"sigstore/cosign-installer",
	}
	slsaReusablePrefix = "slsa-framework/slsa-github-generator"

	// Steps that publish release-shaped artifacts. Heuristic: a workflow with
	// any of these in any job is "producing" something that consumers should
	// be able to verify.
	releaseArtifactActionPrefixes = []string{
		"softprops/action-gh-release",
		"actions/upload-release-asset",
		"docker/build-push-action",
		"actions/upload-pages-artifact",
	}

	// Verification step matchers (CLI commands; we search inline run scripts).
	verifyCommandRe = regexp.MustCompile(`\b(gh\s+attestation\s+verify|slsa-verifier\s+verify|cosign\s+verify-attestation|cosign\s+verify\b)`)
	releaseRunRe    = regexp.MustCompile(`(?i)\b(docker\s+push\b|gh\s+release\s+upload\b|gh\s+release\s+create\b|npm\s+publish\b|cargo\s+publish\b|twine\s+upload\b|gem\s+push\b|goreleaser\s+release\b)`)

	// PR-controlled context patterns that must not feed a cache key when the
	// workflow runs as `pull_request_target` (cache poisoning).
	prControlledCtxRe = regexp.MustCompile(`github\.(head_ref|event\.pull_request\.head\.(ref|sha|label))|github\.event\.pull_request\.(title|body|number)`)
)

// --- CheckSLSAProvenance ----------------------------------------------------

// CheckSLSAProvenance flags workflows that publish a release-shaped artifact
// without any provenance/signing step. Heuristic: presence of any "publishes"
// action or run-line, absence of every provenance/signing action *and* the
// SLSA reusable workflow.
func CheckSLSAProvenance(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	publishes, publishLine, publishCol := workflowPublishes(workflow, jobs)
	if !publishes {
		return nil
	}
	if workflowHasProvenance(workflow, jobs) {
		return nil
	}
	return []Finding{{
		File:     file,
		Line:     publishLine,
		Column:   publishCol,
		Severity: SeverityHigh,
		Category: "SLSA-BUILD-L2",
		RuleID:   RuleSLSAProvenance,
		Title:    "Build provenance is not generated",
		Description: "This workflow publishes a release artifact (container image, GitHub Release asset, package, …) but does not generate a SLSA Build provenance attestation. Without provenance, consumers cannot verify how the artifact was built.",
		Recommendation: "Add an attestation step using actions/attest-build-provenance (SLSA Build L2) or call the slsa-framework/slsa-github-generator reusable workflow (SLSA Build L3). See https://github.com/actions/attest-build-provenance.",
	}}
}

func workflowPublishes(workflow *WorkflowNode, jobs []JobNodeWithID) (bool, int, int) {
	for _, j := range jobs {
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, s := range steps {
			if stepUsesAny(s, releaseArtifactActionPrefixes...) {
				return true, s.Uses.Line, s.Uses.Column
			}
			if s.Run.Value != "" && releaseRunRe.MatchString(s.Run.Value) {
				return true, s.Run.Line, s.Run.Column
			}
		}
	}
	return false, 0, 0
}

func workflowHasProvenance(workflow *WorkflowNode, jobs []JobNodeWithID) bool {
	// Reusable workflow call (job-level uses:).
	raw := jobsRawForReusable(workflow)
	for _, node := range raw {
		if _, ok := jobUsesReusable(node, slsaReusablePrefix); ok {
			return true
		}
	}
	// In-job attestation steps.
	for _, j := range jobs {
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, s := range steps {
			if stepUsesAny(s, provenanceActionPrefixes...) {
				return true
			}
		}
	}
	return false
}

// --- CheckSLSAProvenanceIsolated -------------------------------------------

// CheckSLSAProvenanceIsolated flags workflows that have in-job attestation
// steps but no slsa-github-generator reusable workflow call. The in-job form
// is L2 only — L3 requires the signing context the user's run-steps can't
// touch, which the reusable workflow provides.
func CheckSLSAProvenanceIsolated(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	raw := jobsRawForReusable(workflow)
	for _, node := range raw {
		if _, ok := jobUsesReusable(node, slsaReusablePrefix); ok {
			return nil // workflow already uses the L3-eligible reusable workflow
		}
	}
	for _, j := range jobs {
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, s := range steps {
			if stepUsesAny(s, provenanceActionPrefixes...) {
				return []Finding{{
					File:     file,
					Line:     s.Uses.Line,
					Column:   s.Uses.Column,
					Severity: SeverityMedium,
					Category: "SLSA-BUILD-L3",
					RuleID:   RuleSLSAProvenanceIsolated,
					Title:    "Provenance generated in-job is not isolated (SLSA L2, not L3)",
					Description: fmt.Sprintf(
						"Job %q signs its own build provenance with %q. This meets SLSA Build L2 but not L3: the user's run-steps share the job's signing context. SLSA L3 requires a trusted reusable workflow to perform signing.",
						j.ID, s.Uses.Value,
					),
					Recommendation: "Move provenance generation into the slsa-framework/slsa-github-generator reusable workflow (e.g. .github/workflows/generator_generic_slsa3.yml@vX.Y.Z) and consume its digests output from this build job.",
				}}
			}
		}
	}
	return nil
}

// --- CheckSLSAOIDCTokenScope -----------------------------------------------

// CheckSLSAOIDCTokenScope flags jobs that use attest/cosign/slsa-generator
// signing tooling but don't declare id-token: write at the job level (and the
// workflow-level permissions don't already grant it).
func CheckSLSAOIDCTokenScope(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	if hasIDTokenWrite(&workflow.Permissions) {
		// Workflow-level grant; no per-job grant needed.
		return nil
	}
	var findings []Finding
	raw := jobsRawForReusable(workflow)

	for _, j := range jobs {
		needsToken := false
		var line, col int
		var trigger string

		// Reusable workflow call: SLSA generator always needs id-token: write.
		if node, ok := raw[j.ID]; ok {
			if uses, match := jobUsesReusable(node, slsaReusablePrefix); match {
				needsToken = true
				line, col = j.Line, j.Column
				trigger = uses
			}
		}

		// Step-level signing tooling.
		if !needsToken && j.Node.Steps.Kind == yaml.SequenceNode {
			var steps []StepNode
			if err := j.Node.Steps.Decode(&steps); err == nil {
				for _, s := range steps {
					if stepUsesAny(s, signingActionPrefixes...) {
						needsToken = true
						line, col = s.Uses.Line, s.Uses.Column
						trigger = s.Uses.Value
						break
					}
					if s.Run.Value != "" && strings.Contains(s.Run.Value, "cosign sign") {
						needsToken = true
						line, col = s.Run.Line, s.Run.Column
						trigger = "cosign sign"
						break
					}
				}
			}
		}

		if !needsToken {
			continue
		}
		if hasIDTokenWrite(&j.Node.Permissions) {
			continue
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     line,
			Column:   col,
			Severity: SeverityMedium,
			Category: "SLSA-BUILD-L2",
			RuleID:   RuleSLSAOIDCTokenScope,
			Title:    "Provenance/signing step is missing id-token: write permission",
			Description: fmt.Sprintf(
				"Job %q uses %q for keyless signing or attestation, but neither the workflow nor the job declares permissions.id-token: write. The OIDC token Sigstore needs to mint signatures will be unavailable.",
				j.ID, trigger,
			),
			Recommendation: "Add a permissions block on this job (or the workflow) granting id-token: write alongside any other scopes the job needs (e.g. contents: read, attestations: write).",
		})
	}
	return findings
}

// --- CheckSLSAPermsOverlyBroad ---------------------------------------------

// CheckSLSAPermsOverlyBroad flags an explicit permissions block that grants
// write-all (the antipattern that's strictly worse than no block: it makes
// the maintainer think they applied least privilege when they actually
// granted everything).
func CheckSLSAPermsOverlyBroad(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding
	if isWriteAllPermissions(&workflow.Permissions) {
		findings = append(findings, Finding{
			File:     file,
			Line:     workflow.Permissions.Line,
			Column:   workflow.Permissions.Column,
			Severity: SeverityHigh,
			Category: "SLSA-BUILD-L2",
			RuleID:   RuleSLSAPermsOverlyBroad,
			Title:    "Workflow permissions grant write-all",
			Description: "The workflow-level permissions block grants write to every scope. This is no better than the implicit default — SLSA Build L2 expects least privilege.",
			Recommendation: "Replace write-all with the smallest set of scopes the workflow actually needs (e.g. `permissions: { contents: read }`), and grant additional writes only on the specific jobs that require them.",
		})
	}
	for _, j := range jobs {
		if isWriteAllPermissions(&j.Node.Permissions) {
			findings = append(findings, Finding{
				File:     file,
				Line:     j.Node.Permissions.Line,
				Column:   j.Node.Permissions.Column,
				Severity: SeverityHigh,
				Category: "SLSA-BUILD-L2",
				RuleID:   RuleSLSAPermsOverlyBroad,
				Title:    fmt.Sprintf("Job %q permissions grant write-all", j.ID),
				Description: fmt.Sprintf(
					"Job %q declares a permissions block that grants write to every scope. SLSA Build L2 expects least privilege.",
					j.ID,
				),
				Recommendation: "Replace write-all with the smallest set of scopes the job actually needs.",
			})
		}
	}
	return findings
}

func isWriteAllPermissions(perm *yaml.Node) bool {
	if perm == nil || perm.Kind == 0 {
		return false
	}
	if perm.Kind == yaml.ScalarNode {
		return strings.EqualFold(perm.Value, "write-all")
	}
	if perm.Kind == yaml.MappingNode {
		if len(perm.Content) == 0 {
			return false
		}
		allWrite := true
		seen := 0
		for i := 0; i+1 < len(perm.Content); i += 2 {
			seen++
			if !strings.EqualFold(perm.Content[i+1].Value, "write") {
				allWrite = false
				break
			}
		}
		// Only flag exhaustive write maps with >= 4 scopes (the GitHub-defined
		// "all scopes" list is ~10 entries; the threshold avoids flagging a
		// targeted "contents: write" block).
		return allWrite && seen >= 4
	}
	return false
}

// --- CheckSLSACachePoisoning ------------------------------------------------

// CheckSLSACachePoisoning flags actions/cache (or actions/cache/restore) keys
// derived from PR-controlled inputs in workflows that run with elevated
// pull_request_target privileges. An attacker controls the cache namespace
// and can plant payloads consumed by the trusted base branch.
func CheckSLSACachePoisoning(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	if !onTriggers(workflow, "pull_request_target") {
		return nil
	}
	var findings []Finding
	for _, j := range jobs {
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, s := range steps {
			if !stepUsesAny(s, "actions/cache") {
				continue
			}
			if s.With.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(s.With.Content); i += 2 {
				k := s.With.Content[i].Value
				if k != "key" && k != "restore-keys" {
					continue
				}
				v := s.With.Content[i+1].Value
				if prControlledCtxRe.MatchString(v) {
					findings = append(findings, Finding{
						File:     file,
						Line:     s.With.Content[i+1].Line,
						Column:   s.With.Content[i+1].Column,
						Severity: SeverityHigh,
						Category: "SLSA-BUILD-L3",
						RuleID:   RuleSLSACachePoisoning,
						Title:    "Cache key in pull_request_target workflow derives from PR-controlled input",
						Description: fmt.Sprintf(
							"Job %q runs as pull_request_target (privileged context) and caches with key %q. An attacker can poison the cache for the base branch — violating SLSA Build L3 isolation.",
							j.ID, v,
						),
						Recommendation: "Use a key that depends only on trusted, base-branch state (e.g. github.sha of the base branch, lockfile hash). For PR-specific caching, move the cache step into a separate pull_request workflow without elevated permissions.",
					})
				}
			}
		}
	}
	return findings
}

// --- CheckSLSAVerifyStep ----------------------------------------------------

// CheckSLSAVerifyStep emits an INFO finding when the workflow consumes
// artifacts (downloads or pulls images) but no verification step is present.
// This is a recommendation, not a security defect — INFO severity keeps it
// out of failure thresholds by default.
func CheckSLSAVerifyStep(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	consumes, line, col := workflowConsumesArtifacts(workflow, jobs)
	if !consumes {
		return nil
	}
	if workflowHasVerify(workflow, jobs) {
		return nil
	}
	return []Finding{{
		File:     file,
		Line:     line,
		Column:   col,
		Severity: SeverityInfo,
		Category: "SLSA-BUILD-L2",
		RuleID:   RuleSLSAVerifyStep,
		Title:    "Workflow consumes artifacts but does not verify provenance",
		Description: "This workflow downloads artifacts or pulls a container image without a provenance-verification step. SLSA Build L2's consumer side is unfulfilled unless artifacts are verified before use.",
		Recommendation: "Add a verification step before using the artifact, e.g.: `gh attestation verify <file> --owner <org>`, `slsa-verifier verify-artifact ...`, or `cosign verify-attestation ...`.",
	}}
}

func workflowConsumesArtifacts(workflow *WorkflowNode, jobs []JobNodeWithID) (bool, int, int) {
	consumeRe := regexp.MustCompile(`(?i)\b(docker\s+pull\b|docker\s+run\s+\S|crane\s+pull\b|skopeo\s+copy\b)`)
	for _, j := range jobs {
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, s := range steps {
			if stepUsesAny(s, "actions/download-artifact") {
				return true, s.Uses.Line, s.Uses.Column
			}
			if s.Run.Value != "" && consumeRe.MatchString(s.Run.Value) {
				return true, s.Run.Line, s.Run.Column
			}
		}
	}
	return false, 0, 0
}

func workflowHasVerify(workflow *WorkflowNode, jobs []JobNodeWithID) bool {
	for _, j := range jobs {
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, s := range steps {
			if s.Run.Value != "" && verifyCommandRe.MatchString(s.Run.Value) {
				return true
			}
			if stepUsesAny(s, "slsa-framework/slsa-verifier-action") {
				return true
			}
		}
	}
	return false
}
