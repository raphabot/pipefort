package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow checks covering the OWASP CI/CD Top 10 categories that the original
// rules.go did not address: CICD-SEC-2 (Inadequate IAM), CICD-SEC-7 (Insecure
// System Configuration), CICD-SEC-8 (Ungoverned 3rd-Party Services), CICD-SEC-9
// (Improper Artifact Integrity Validation), CICD-SEC-10 (Insufficient Logging
// and Visibility).
//
// Each check follows the same shape as rules.go / slsa_rules.go: takes
// (file, workflow, jobs), returns []Finding, no false positives by default.

// --- CICD-SEC-2: Inadequate Identity & Access Management --------------------

// patSecretRe matches secret names that look like long-lived personal access
// tokens. We deliberately do not match the literal "github_token" name because
// that is the short-lived per-run token GitHub mints automatically, which is
// the recommended replacement for a PAT.
var patSecretRe = regexp.MustCompile(`(?i)(^|_)(pat|personal[_-]?access[_-]?token|gh[_-]?token|gh[_-]?pat|github[_-]?pat)(_|$)`)

// CheckLongLivedPAT flags secrets-context references whose name strongly
// implies a long-lived personal access token. We walk env blocks (workflow,
// job, step) and `with:` inputs on steps; the literal GITHUB_TOKEN is excluded.
func CheckLongLivedPAT(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	findings = append(findings, scanEnvForPATSecret(file, &workflow.Env, "workflow")...)

	for _, jobWrap := range jobs {
		j := jobWrap
		findings = append(findings, scanEnvForPATSecret(file, &j.Node.Env, fmt.Sprintf("job %q", j.ID))...)

		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			findings = append(findings, scanEnvForPATSecret(file, &s.Env, fmt.Sprintf("step %q in job %q", stepName(&s), j.ID))...)
			findings = append(findings, scanWithForPATSecret(file, &s.With, fmt.Sprintf("step %q in job %q", stepName(&s), j.ID))...)
		}
	}
	return findings
}

func scanEnvForPATSecret(file string, envNode *yaml.Node, scope string) []Finding {
	if envNode == nil || envNode.Kind != yaml.MappingNode {
		return nil
	}
	var findings []Finding
	for i := 0; i+1 < len(envNode.Content); i += 2 {
		valNode := envNode.Content[i+1]
		if f, ok := patFindingFromSecretExpr(file, valNode, scope); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func scanWithForPATSecret(file string, withNode *yaml.Node, scope string) []Finding {
	if withNode == nil || withNode.Kind != yaml.MappingNode {
		return nil
	}
	var findings []Finding
	for i := 0; i+1 < len(withNode.Content); i += 2 {
		valNode := withNode.Content[i+1]
		if f, ok := patFindingFromSecretExpr(file, valNode, scope); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

// secretsRefRe captures every `${{ secrets.NAME }}` reference inside a string.
var secretsRefRe = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}`)

func patFindingFromSecretExpr(file string, node *yaml.Node, scope string) (Finding, bool) {
	if node == nil {
		return Finding{}, false
	}
	matches := secretsRefRe.FindAllStringSubmatch(node.Value, -1)
	for _, m := range matches {
		name := m[1]
		if strings.EqualFold(name, "GITHUB_TOKEN") {
			continue
		}
		if !patSecretRe.MatchString(name) {
			continue
		}
		return Finding{
			File:     file,
			Line:     node.Line,
			Column:   node.Column,
			Severity: SeverityMedium,
			Category: "CICD-SEC-2",
			RuleID:   RuleLongLivedPAT,
			Title:    "Long-lived personal access token used in workflow",
			Description: fmt.Sprintf(
				"%s references secret %q, whose name indicates a long-lived personal access token. "+
					"PATs are statically credentialed identities, often tied to a single human account, that survive employee turnover and are difficult to rotate.",
				scope, name,
			),
			Recommendation: "Replace the PAT with the per-run GITHUB_TOKEN (declare the smallest permissions you need) or, for cross-repository operations, configure a GitHub App installation token or OIDC federation to your cloud provider.",
		}, true
	}
	return Finding{}, false
}

// --- CICD-SEC-6 (extension): Secret printed to logs / written to output ------

var (
	// rePrintSecret matches a print-family command echoing a secrets-context
	// value. Scoped to print verbs so a plain assignment (VAR=${{ secrets.X }})
	// — which is the recommended way to pass a secret to a step — isn't flagged.
	rePrintSecret = regexp.MustCompile(`(?i)\b(echo|printf|print|cat|console\.log)\b[^\n]*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}`)
	// reSecretToOutput matches a secret redirected into $GITHUB_OUTPUT/$GITHUB_ENV.
	reSecretToOutput = regexp.MustCompile(`(?i)\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}[^\n]*>>?\s*"?\$?\{?(GITHUB_OUTPUT|GITHUB_ENV)`)
	// reSetOutputSecret matches the legacy ::set-output workflow command carrying a secret.
	reSetOutputSecret = regexp.MustCompile(`(?i)::set-output[^\n]*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}`)
)

// CheckSecretInRunOutput flags inline scripts that print a secret to logs or
// persist it to step output/env, both of which defeat GitHub's log masking.
func CheckSecretInRunOutput(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding
	for _, jobWrap := range jobs {
		j := jobWrap
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			if s.Run.Value == "" {
				continue
			}
			if !rePrintSecret.MatchString(s.Run.Value) &&
				!reSecretToOutput.MatchString(s.Run.Value) &&
				!reSetOutputSecret.MatchString(s.Run.Value) {
				continue
			}
			findings = append(findings, Finding{
				File:     file,
				Line:     s.Run.Line,
				Column:   s.Run.Column,
				Severity: SeverityHigh,
				Category: "CICD-SEC-6",
				RuleID:   RuleSecretInRunOutput,
				Title:    "Secret printed to logs or written to step output",
				Description: fmt.Sprintf(
					"Step %q in job %q prints a secrets-context value to logs or writes it to $GITHUB_OUTPUT/$GITHUB_ENV/::set-output. "+
						"GitHub masks a secret only where it recognizes the exact value; echoing it (often transformed) or persisting it to outputs defeats masking and exposes it to later steps and anyone who can read the run.",
					stepName(&s), j.ID,
				),
				Recommendation: "Never echo secrets or write them to step outputs/env. Pass the secret directly to the consuming step via env: and reference it there; if you must persist a derived value, store it as a masked secret rather than plaintext output.",
			})
		}
	}
	return findings
}

// --- CICD-SEC-7: Insecure System Configuration ------------------------------

// debugLogEnvKeys is the closed set of GitHub-recognised debug-logging
// environment variables. Setting any of them to a truthy value enables verbose
// runner/step logs that include unmasked environment values.
var debugLogEnvKeys = map[string]bool{
	"ACTIONS_STEP_DEBUG":   true,
	"ACTIONS_RUNNER_DEBUG": true,
}

// CheckDebugLoggingEnabled flags workflow/job/step env blocks that turn on the
// GitHub Actions debug-logging knobs.
func CheckDebugLoggingEnabled(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	findings = append(findings, scanEnvForDebugLogging(file, &workflow.Env, "workflow")...)

	for _, jobWrap := range jobs {
		j := jobWrap
		findings = append(findings, scanEnvForDebugLogging(file, &j.Node.Env, fmt.Sprintf("job %q", j.ID))...)
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			findings = append(findings, scanEnvForDebugLogging(file, &s.Env, fmt.Sprintf("step %q in job %q", stepName(&s), j.ID))...)
		}
	}
	return findings
}

func scanEnvForDebugLogging(file string, envNode *yaml.Node, scope string) []Finding {
	if envNode == nil || envNode.Kind != yaml.MappingNode {
		return nil
	}
	var findings []Finding
	for i := 0; i+1 < len(envNode.Content); i += 2 {
		key := envNode.Content[i].Value
		val := envNode.Content[i+1]
		if !debugLogEnvKeys[strings.ToUpper(key)] {
			continue
		}
		if !isTruthyEnvValue(val.Value) {
			continue
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     val.Line,
			Column:   val.Column,
			Severity: SeverityHigh,
			Category: "CICD-SEC-7",
			RuleID:   RuleDebugLoggingEnabled,
			Title:    "Actions debug logging enabled in workflow",
			Description: fmt.Sprintf(
				"%s sets %s to %q. Debug logging emits the values of every step's environment, including masked secrets in some failure paths, to logs that anyone with read access to the run can see.",
				scope, key, val.Value,
			),
			Recommendation: "Remove the debug-logging env entry. If you need it temporarily, enable it as a re-run option ('Enable debug logging') rather than committing it to the workflow.",
		})
	}
	return findings
}

func isTruthyEnvValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// --- CICD-SEC-8: Ungoverned Usage of 3rd Party Services ---------------------

// CheckRepoDispatchUnfiltered flags workflows triggered by repository_dispatch
// without an explicit types: allowlist. Without it, any caller with a
// repo-scoped token can fire the workflow with arbitrary event_type and
// client_payload — effectively granting third-party services an unbounded
// trigger surface.
func CheckRepoDispatchUnfiltered(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	on := workflow.On
	switch on.Kind {
	case yaml.ScalarNode:
		if on.Value == "repository_dispatch" {
			return []Finding{repoDispatchFinding(file, on.Line, on.Column)}
		}
	case yaml.SequenceNode:
		for _, it := range on.Content {
			if it.Value == "repository_dispatch" {
				return []Finding{repoDispatchFinding(file, it.Line, it.Column)}
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			if on.Content[i].Value != "repository_dispatch" {
				continue
			}
			cfg := on.Content[i+1]
			// A mapping with a non-empty `types:` list satisfies the rule.
			if cfg.Kind == yaml.MappingNode && hasNonEmptyTypes(cfg) {
				return nil
			}
			return []Finding{repoDispatchFinding(file, on.Content[i].Line, on.Content[i].Column)}
		}
	}
	return nil
}

func hasNonEmptyTypes(cfg *yaml.Node) bool {
	for i := 0; i+1 < len(cfg.Content); i += 2 {
		if cfg.Content[i].Value != "types" {
			continue
		}
		t := cfg.Content[i+1]
		switch t.Kind {
		case yaml.SequenceNode:
			return len(t.Content) > 0
		case yaml.ScalarNode:
			return strings.TrimSpace(t.Value) != ""
		}
	}
	return false
}

func repoDispatchFinding(file string, line, col int) Finding {
	return Finding{
		File:     file,
		Line:     line,
		Column:   col,
		Severity: SeverityMedium,
		Category: "CICD-SEC-8",
		RuleID:   RuleRepoDispatchUnfilt,
		Title:    "repository_dispatch trigger without event-type allowlist",
		Description: "The workflow is triggered by repository_dispatch but does not declare an explicit types: allowlist. " +
			"Any third-party service or holder of a repo-scoped token can dispatch arbitrary event types with arbitrary client_payload values, gaining a wide trigger surface that bypasses repository governance.",
		Recommendation: "Constrain the trigger to a known list of event types: `on: { repository_dispatch: { types: [my-event] } }`. Validate client_payload values defensively inside the workflow.",
	}
}

// --- CICD-SEC-9: Improper Artifact Integrity Validation ---------------------

// downloadCmdRe matches a curl/wget invocation that saves its output to a file
// path with a binary/archive extension. We only flag downloads to disk: piping
// to a shell is already covered by BEST-PRAC-1.
var downloadCmdRe = regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*?(\.(?:tar(?:\.gz|\.xz|\.bz2)?|tgz|zip|deb|rpm|pkg|msi|exe|jar|war|whl|gem|apk|so|dll|dylib|bin|run|sh|7z))\b`)

// integrityVerifyRe matches commands that establish artifact integrity in the
// same step. Wide on purpose: any of these turns off the check.
var integrityVerifyRe = regexp.MustCompile(`(?i)\b(sha(?:256|512)sum\b|shasum\b|openssl\s+dgst\b|gpg\s+--verify\b|cosign\s+verify\b|cosign\s+verify-(?:blob|attestation)\b|slsa-verifier\s+verify\b|gh\s+attestation\s+verify\b|minisign\s+-V\b|signify\s+-V\b)`)

// CheckDownloadWithoutChecksum flags inline scripts that download a binary or
// archive without a paired integrity-verification command in the same step.
func CheckDownloadWithoutChecksum(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding
	for _, jobWrap := range jobs {
		j := jobWrap
		if j.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := j.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			if s.Run.Value == "" {
				continue
			}
			m := downloadCmdRe.FindStringSubmatch(s.Run.Value)
			if m == nil {
				continue
			}
			if integrityVerifyRe.MatchString(s.Run.Value) {
				continue
			}
			findings = append(findings, Finding{
				File:     file,
				Line:     s.Run.Line,
				Column:   s.Run.Column,
				Severity: SeverityMedium,
				Category: "CICD-SEC-9",
				RuleID:   RuleDownloadNoChecksum,
				Title:    "Downloaded artifact has no integrity check",
				Description: fmt.Sprintf(
					"Step %q in job %q downloads %s but does not verify the artifact's integrity (checksum, signature, or provenance) in the same step. "+
						"If the upstream is tampered with or the connection is hijacked, the workflow will execute compromised bytes.",
					stepName(&s), j.ID, m[2],
				),
				Recommendation: "Verify the download in the same step before using it: e.g. `echo \"<sha256>  file\" | sha256sum -c -`, `cosign verify-blob`, `gpg --verify`, or `gh attestation verify`.",
			})
		}
	}
	return findings
}

// --- CICD-SEC-10: Insufficient Logging & Visibility -------------------------

// CheckContinueOnErrorJob flags jobs that declare continue-on-error: true at
// the job level. A job-level `continue-on-error: true` causes the job's
// conclusion to be reported as success even when its steps fail, so required-
// check gates, branch-protection enforcement, and audit dashboards lose
// visibility into the failure.
func CheckContinueOnErrorJob(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	raw := jobsRawForReusable(workflow)
	var findings []Finding
	for _, jobWrap := range jobs {
		j := jobWrap
		node, ok := raw[j.ID]
		if !ok || node == nil || node.Kind != yaml.MappingNode {
			continue
		}
		val := jobMappingValue(node, "continue-on-error")
		if val == nil {
			continue
		}
		// `continue-on-error: ${{ ... }}` may be intentionally dynamic — only
		// flag literal true / "true".
		if !isLiteralTrue(val) {
			continue
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     val.Line,
			Column:   val.Column,
			Severity: SeverityLow,
			Category: "CICD-SEC-10",
			RuleID:   RuleContinueOnErrorJob,
			Title:    "Job-level continue-on-error suppresses failure visibility",
			Description: fmt.Sprintf(
				"Job %q declares continue-on-error: true at the job level. GitHub reports the job's conclusion as success even when its steps fail, so required-check gates, branch-protection enforcement, and audit dashboards never see the failure.",
				j.ID,
			),
			Recommendation: "Remove continue-on-error at the job level. If a specific step is expected to fail without failing the job, scope continue-on-error to that step instead and log the failure explicitly.",
		})
	}
	return findings
}

func jobMappingValue(jobNode *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(jobNode.Content); i += 2 {
		if jobNode.Content[i].Value == key {
			return jobNode.Content[i+1]
		}
	}
	return nil
}

func isLiteralTrue(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(node.Value), "true")
}
