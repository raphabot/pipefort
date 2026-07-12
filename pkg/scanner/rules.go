package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// JobNodeWithID wraps a JobNode with its mapping key (ID).
type JobNodeWithID struct {
	ID     string
	Line   int
	Column int
	Node   JobNode
}

// rePPEUntrustedCtx matches GitHub expression interpolations of
// attacker-controllable context. Beyond github.event.* metadata (PR/issue
// titles, comment bodies, commit messages) it also covers github.head_ref —
// the source branch name on a fork PR, which an attacker fully controls — and
// the review/discussion/pages/workflow_run event payloads. The fixer in
// fixer.go reuses this exact regex when hoisting matches into env vars, so the
// two never drift.
var rePPEUntrustedCtx = regexp.MustCompile(`\$\{\{\s*github\.(head_ref|event\.(pull_request|issue|issues|comment|head_commit|commits|review|review_comment|discussion|discussion_comment|pages|workflow_run)[\w\.\*\[\]'"\-]*)\s*\}\}`)

// CheckPPE checks for Poisoned Pipeline Execution (CICD-SEC-4) — untrusted
// github context interpolated into code. Two injection surfaces are covered:
// inline run: scripts, and action with: inputs that are evaluated as code
// (most notably actions/github-script's `script:` input).
func CheckPPE(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}

		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}

		for _, step := range steps {
			s := step

			// Inline run scripts.
			if matches := rePPEUntrustedCtx.FindAllString(s.Run.Value, -1); len(matches) > 0 {
				findings = append(findings, Finding{
					File:     file,
					Line:     s.Run.Line,
					Column:   s.Run.Column,
					Severity: SeverityHigh,
					Category: "CICD-SEC-4",
					RuleID:   RulePPEShellInjection,
					Title:    "Poisoned Pipeline Execution (Shell Injection)",
					Description: fmt.Sprintf(
						"Step %q in job %q contains inline script shell injection risk. "+
							"It references untrusted event data directly in the script block: %v. "+
							"An attacker could manipulate pull request/issue titles, comments, commit messages, or the head branch name to execute arbitrary code.",
						stepName(&s), jobWrap.ID, matches,
					),
					Recommendation: "Assign the untrusted context variable to an environment variable in the step, and reference it via the environment (e.g. '$VAR' instead of '${{ github.event... }}').",
				})
			}

			// Action `with:` inputs. Actions like actions/github-script evaluate
			// an input (e.g. `script:`) as code, so an interpolated untrusted
			// context is injectable exactly like an inline run: script.
			if s.With.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(s.With.Content); i += 2 {
					keyNode := s.With.Content[i]
					valNode := s.With.Content[i+1]
					if valNode.Kind != yaml.ScalarNode {
						continue
					}
					matches := rePPEUntrustedCtx.FindAllString(valNode.Value, -1)
					if len(matches) == 0 {
						continue
					}
					findings = append(findings, Finding{
						File:     file,
						Line:     valNode.Line,
						Column:   valNode.Column,
						Severity: SeverityHigh,
						Category: "CICD-SEC-4",
						RuleID:   RulePPEShellInjection,
						Title:    "Poisoned Pipeline Execution (Shell Injection)",
						Description: fmt.Sprintf(
							"Step %q in job %q interpolates untrusted event data %v into the %q input of action %q. "+
								"Inputs evaluated as code (e.g. actions/github-script's 'script') let an attacker who controls that event data run arbitrary code.",
							stepName(&s), jobWrap.ID, matches, keyNode.Value, s.Uses.Value,
						),
						Recommendation: "Pass the untrusted value through an intermediate env: variable and read it from the environment inside the action (e.g. process.env.VAR), instead of interpolating ${{ github.* }} into the input.",
					})
				}
			}
		}
	}

	return findings
}

// CheckPBAC checks for Pipeline-Based Access Controls (CICD-SEC-5)
// specifically missing top-level and job-level permissions blocks.
func CheckPBAC(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	// Check if workflow has top-level permissions
	hasWorkflowPermissions := workflow.Permissions.Kind != 0

	// Check if ALL jobs have job-level permissions
	allJobsHavePermissions := true
	if len(jobs) > 0 {
		for _, jobWrap := range jobs {
			if jobWrap.Node.Permissions.Kind == 0 {
				allJobsHavePermissions = false
				break
			}
		}
	} else {
		allJobsHavePermissions = false
	}

	if !hasWorkflowPermissions && !allJobsHavePermissions {
		findings = append(findings, Finding{
			File:     file,
			Line:     1, // Fallback to top of file
			Column:   1,
			Severity: SeverityMedium,
			Category: "CICD-SEC-5",
			RuleID:   RuleMissingPermissions,
			Title:    "Missing Permissions Specification",
			Description: "The workflow does not specify explicit 'permissions' at either the workflow level or the job level. " +
				"It will default to standard GitHub token permissions, which might be overly permissive (e.g., write-access) depending on repository/org settings.",
			Recommendation: "Specify restrictive permissions at the workflow or job level (e.g., 'permissions: read-all' or 'permissions: {}' as a default, and grant write permissions only where strictly necessary).",
		})
	}

	return findings
}

// CheckUnpinnedActions checks for Dependency Chain Abuse (CICD-SEC-3)
// specifically referencing third-party actions by tag/branch instead of full commit SHA.
func CheckUnpinnedActions(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	// Regex for 40-character SHA-1 hash (common for git commits)
	reSHA := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}

		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}

		for _, step := range steps {
			usesVal := step.Uses.Value
			if usesVal == "" {
				continue
			}

			// Ignore local actions (starting with "./" or ".github/")
			if strings.HasPrefix(usesVal, "./") || strings.HasPrefix(usesVal, ".github/") {
				continue
			}

			// Action format is: owner/repo@ref or owner/repo/path@ref
			parts := strings.Split(usesVal, "@")
			if len(parts) != 2 {
				continue
			}

			ref := parts[1]
			if !reSHA.MatchString(ref) {
				findings = append(findings, Finding{
					File:     file,
					Line:     step.Uses.Line,
					Column:   step.Uses.Column,
					Severity: SeverityMedium,
					Category: "CICD-SEC-3",
					RuleID:   RuleUnpinnedAction,
					Title:    "Unpinned Third-Party Action",
					Description: fmt.Sprintf(
						"Step %q in job %q uses third-party action %q without pinning it to a full commit SHA. "+
							"Tags or branch references (like %q) are mutable and can be updated by maintainers or compromised by attackers.",
						stepName(&step), jobWrap.ID, usesVal, ref,
					),
					Recommendation: fmt.Sprintf("Pin the action to a specific commit SHA, and add a comment with the original tag name (e.g. %s@%s # %s).", parts[0], "[commit-sha]", ref),
				})
			}
		}
	}

	return findings
}

// untrustedCheckoutRefSubstrings are the interpolations/refs that resolve to
// attacker-controlled code when checked out inside a privileged trigger:
// pull_request head metadata, the head_ref branch name, the refs/pull/N/{head,
// merge} pseudo-refs, and the upstream-run head for workflow_run.
var untrustedCheckoutRefSubstrings = []string{
	"github.event.pull_request.head",
	"github.head_ref",
	"refs/pull/",
	"github.event.workflow_run.head",
}

func isUntrustedCheckoutRef(v string) bool {
	for _, sub := range untrustedCheckoutRefSubstrings {
		if strings.Contains(v, sub) {
			return true
		}
	}
	return false
}

// CheckUntrustedPullRequestTarget checks for Insufficient Flow Control (CICD-SEC-1):
// a privileged trigger (pull_request_target or workflow_run) that checks out the
// untrusted head ref and then runs tests/builds with secrets in scope.
func CheckUntrustedPullRequestTarget(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	// 1. Both pull_request_target and workflow_run run in the privileged base
	//    context (repo secrets + write token) while operating on a fork PR's
	//    code, so checking out that code is dangerous under either.
	if !onTriggers(workflow, "pull_request_target", "workflow_run") {
		return nil
	}

	// 2. Scan jobs for checking out the untrusted head ref.
	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}

		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}

		checksOutPRHead := false
		var checkoutStep *StepNode

		for _, step := range steps {
			s := step
			if strings.HasPrefix(s.Uses.Value, "actions/checkout") {
				// Check if checkout uses "with" to target an untrusted ref
				// e.g. ref: ${{ github.event.pull_request.head.sha }}
				if s.With.Kind == yaml.MappingNode {
					for i := 0; i < len(s.With.Content); i += 2 {
						keyNode := s.With.Content[i]
						valNode := s.With.Content[i+1]
						if keyNode.Value == "ref" && isUntrustedCheckoutRef(valNode.Value) {
							checksOutPRHead = true
							checkoutStep = &s
							break
						}
					}
				}
			}
		}

		if checksOutPRHead {
			findings = append(findings, Finding{
				File:     file,
				Line:     checkoutStep.Uses.Line,
				Column:   checkoutStep.Uses.Column,
				Severity: SeverityHigh,
				Category: "CICD-SEC-1",
				RuleID:   RulePPECheckout,
				Title:    "Dangerous Checkout in pull_request_target Workflow",
				Description: fmt.Sprintf(
					"Job %q runs on a privileged trigger (pull_request_target or workflow_run) and checks out untrusted code from the pull request head branch. "+
						"Because these triggers run in the context of the base branch with repository secrets and write permissions, "+
						"subsequent build, test, or lint steps can be exploited by an attacker to steal secrets or run malicious commands with elevated privileges.",
					jobWrap.ID,
				),
				Recommendation: "Avoid checking out untrusted code inside pull_request_target/workflow_run workflows. If you must inspect PR code, write a script that does not run tests/builds automatically, or use a standard 'pull_request' trigger instead.",
			})
		}
	}

	return findings
}

// ghRunDownloadRe matches the `gh run download` CLI used to pull artifacts
// from another workflow run.
var ghRunDownloadRe = regexp.MustCompile(`(?i)\bgh\s+run\s+download\b`)

// CheckWorkflowRunArtifactPoisoning flags workflow_run workflows that download
// artifacts produced by the (untrusted) triggering run. A fork PR can upload a
// poisoned artifact the privileged workflow_run then trusts (CICD-SEC-1).
func CheckWorkflowRunArtifactPoisoning(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	if !onTriggers(workflow, "workflow_run") {
		return nil
	}
	var findings []Finding
	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			line, col := s.Uses.Line, s.Uses.Column
			downloads := strings.HasPrefix(s.Uses.Value, "actions/download-artifact") ||
				strings.HasPrefix(s.Uses.Value, "dawidd6/action-download-artifact")
			if !downloads && ghRunDownloadRe.MatchString(s.Run.Value) {
				downloads = true
				line, col = s.Run.Line, s.Run.Column
			}
			if !downloads {
				continue
			}
			findings = append(findings, Finding{
				File:     file,
				Line:     line,
				Column:   col,
				Severity: SeverityHigh,
				Category: "CICD-SEC-1",
				RuleID:   RuleWorkflowRunArtifactPoisoning,
				Title:    "workflow_run downloads artifacts from the triggering run",
				Description: fmt.Sprintf(
					"Job %q runs on workflow_run and downloads artifacts (step %q) produced by the triggering run. "+
						"A fork pull request can upload a poisoned artifact that this privileged workflow trusts, leading to code execution or content injection in the base-repository context.",
					jobWrap.ID, stepName(&s),
				),
				Recommendation: "Treat downloaded artifacts as untrusted: validate their contents before use, never execute them, and don't feed them into steps that hold repository secrets or a writable token.",
			})
		}
	}
	return findings
}

// CheckCheckoutPersistCredentials flags actions/checkout steps inside a
// privileged-trigger workflow that don't disable persist-credentials, leaving
// the job token in .git/config for later untrusted steps (CICD-SEC-1).
func CheckCheckoutPersistCredentials(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	if !onTriggers(workflow, "pull_request_target", "workflow_run") {
		return nil
	}
	var findings []Finding
	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			s := step
			if !strings.HasPrefix(s.Uses.Value, "actions/checkout") {
				continue
			}
			if checkoutDisablesPersistCreds(&s.With) {
				continue
			}
			findings = append(findings, Finding{
				File:     file,
				Line:     s.Uses.Line,
				Column:   s.Uses.Column,
				Severity: SeverityMedium,
				Category: "CICD-SEC-1",
				RuleID:   RuleCheckoutPersistCreds,
				Title:    "Checkout persists credentials under a privileged trigger",
				Description: fmt.Sprintf(
					"Job %q runs on a privileged trigger (pull_request_target or workflow_run) and step %q uses actions/checkout without persist-credentials: false. "+
						"The job's token is written to .git/config, where any later step running untrusted code can read and abuse it.",
					jobWrap.ID, stepName(&s),
				),
				Recommendation: "Set 'with: persist-credentials: false' on the checkout step so the token is not left in the workspace for later steps.",
			})
		}
	}
	return findings
}

// checkoutDisablesPersistCreds reports whether a checkout step's with: block
// explicitly sets persist-credentials: false.
func checkoutDisablesPersistCreds(with *yaml.Node) bool {
	if with == nil || with.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(with.Content); i += 2 {
		if with.Content[i].Value == "persist-credentials" {
			return strings.EqualFold(strings.TrimSpace(with.Content[i+1].Value), "false")
		}
	}
	return false
}

// CheckSecretsInheritPRTarget flags jobs that call a reusable workflow with
// secrets: inherit inside a privileged-trigger workflow, handing every
// repository secret to a workflow running in an attacker-influenced context
// (CICD-SEC-4).
func CheckSecretsInheritPRTarget(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	if !onTriggers(workflow, "pull_request_target", "workflow_run") {
		return nil
	}
	raw := jobsRawForReusable(workflow)
	var findings []Finding
	for _, jobWrap := range jobs {
		node, ok := raw[jobWrap.ID]
		if !ok || node == nil || node.Kind != yaml.MappingNode {
			continue
		}
		usesVal := jobMappingValue(node, "uses")
		if usesVal == nil || usesVal.Value == "" {
			continue
		}
		secretsVal := jobMappingValue(node, "secrets")
		if secretsVal == nil || !strings.EqualFold(strings.TrimSpace(secretsVal.Value), "inherit") {
			continue
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     secretsVal.Line,
			Column:   secretsVal.Column,
			Severity: SeverityHigh,
			Category: "CICD-SEC-4",
			RuleID:   RuleSecretsInheritPRTarget,
			Title:    "Reusable workflow called with secrets: inherit under a privileged trigger",
			Description: fmt.Sprintf(
				"Job %q runs on a privileged trigger (pull_request_target or workflow_run) and calls reusable workflow %q with secrets: inherit, "+
					"passing every repository secret into a workflow that executes in an attacker-influenced context.",
				jobWrap.ID, usesVal.Value,
			),
			Recommendation: "Pass only the specific secrets the reusable workflow needs via an explicit `secrets:` map instead of `inherit`, and avoid handing secrets to reusable workflows triggered by untrusted events.",
		})
	}
	return findings
}

// CheckHardcodedSecrets checks for Insufficient Credential Hygiene (CICD-SEC-6)
// specifically finding hardcoded passwords, tokens, API keys.
func CheckHardcodedSecrets(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	// Simple regex patterns for common credentials
	patterns := map[string]*regexp.Regexp{
		"GitHub PAT":     regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
		"Slack Token":    regexp.MustCompile(`\bxoxb-[0-9]{11,13}-[A-Za-z0-9]{24}\b`),
		"AWS Access Key": regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		"Generic Token":  regexp.MustCompile(`\b(?:token|password|secret|key)\s*:=\s*["'][A-Za-z0-9_\-\.\!]{16,}["']`),
	}

	// 1. Check env block in workflow
	findings = append(findings, checkEnvSecrets(file, &workflow.Env, "Workflow-level")...)

	// 2. Check jobs
	for _, jobWrap := range jobs {
		// Check job-level env
		findings = append(findings, checkEnvSecrets(file, &jobWrap.Node.Env, fmt.Sprintf("Job-level %q", jobWrap.ID))...)

		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}

		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}

		for _, step := range steps {
			// Check step-level env
			findings = append(findings, checkEnvSecrets(file, &step.Env, fmt.Sprintf("Step %q in job %q", stepName(&step), jobWrap.ID))...)

			// Check inline run scripts for regex patterns
			if step.Run.Value != "" {
				for name, re := range patterns {
					if loc := re.FindStringIndex(step.Run.Value); loc != nil {
						findings = append(findings, Finding{
							File:     file,
							Line:     step.Run.Line,
							Column:   step.Run.Column,
							Severity: SeverityHigh,
							Category: "CICD-SEC-6",
							RuleID:   RuleHardcodedSecrets,
							Title:    fmt.Sprintf("Hardcoded Credential in Script (%s)", name),
							Description: fmt.Sprintf(
								"A potential hardcoded secret (%s) was found in the inline script of step %q in job %q.",
								name, stepName(&step), jobWrap.ID,
							),
							Recommendation: "Remove the hardcoded credential and reference it via GitHub Secrets instead (e.g. ${{ secrets.SECRET_NAME }}).",
						})
					}
				}
			}
		}
	}

	return findings
}

// checkEnvSecrets checks a YAML MappingNode (representing an env block) for hardcoded secrets.
func checkEnvSecrets(file string, envNode *yaml.Node, scope string) []Finding {
	if envNode.Kind != yaml.MappingNode {
		return nil
	}

	var findings []Finding
	suspiciousKeys := []string{"token", "password", "secret", "key", "webhook", "passwd", "credential"}

	for i := 0; i < len(envNode.Content); i += 2 {
		keyNode := envNode.Content[i]
		valNode := envNode.Content[i+1]

		keyLower := strings.ToLower(keyNode.Value)
		val := valNode.Value

		// If value contains a hardcoded literal (not starting with ${{ and ending with }})
		// and the key contains any of the suspicious key names, flag it.
		isSecretKey := false
		for _, sk := range suspiciousKeys {
			if strings.Contains(keyLower, sk) {
				isSecretKey = true
				break
			}
		}

		if isSecretKey && val != "" {
			trimmedVal := strings.TrimSpace(val)
			isGitHubSecretExpr := strings.HasPrefix(trimmedVal, "${{") && strings.HasSuffix(trimmedVal, "}}")
			
			if !isGitHubSecretExpr {
				findings = append(findings, Finding{
					File:     file,
					Line:     valNode.Line,
					Column:   valNode.Column,
					Severity: SeverityHigh,
					Category: "CICD-SEC-6",
					RuleID:   RuleHardcodedSecrets,
					Title:    "Hardcoded Secret in Environment Variable",
					Description: fmt.Sprintf(
						"Environment variable %q in %s scope is assigned a hardcoded literal value. "+
							"Because the variable name implies it contains a secret or credential, "+
							"this value should be fetched dynamically from GitHub Secrets.",
						keyNode.Value, scope,
					),
					Recommendation: fmt.Sprintf("Store the value in GitHub Secrets and reference it using '${{ secrets.%s }}'.", strings.ToUpper(keyNode.Value)),
				})
			}
		}
	}

	return findings
}

func stepName(step *StepNode) string {
	if step.Name.Value != "" {
		return step.Name.Value
	}
	if step.Uses.Value != "" {
		return step.Uses.Value
	}
	if step.Run.Value != "" {
		// Return first line of run script truncated
		lines := strings.Split(strings.TrimSpace(step.Run.Value), "\n")
		if len(lines[0]) > 30 {
			return lines[0][:27] + "..."
		}
		return lines[0]
	}
	return "unnamed step"
}

// CheckPipeToShell checks if steps run curl/wget and pipe it directly to bash/sh.
func CheckPipeToShell(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding
	rePipeShell := pipeToShellRe

	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			if step.Run.Value == "" {
				continue
			}
			if rePipeShell.MatchString(step.Run.Value) {
				findings = append(findings, Finding{
					File:     file,
					Line:     step.Run.Line,
					Column:   step.Run.Column,
					Severity: SeverityHigh,
					Category: "BEST-PRAC-1",
					RuleID:   RulePipeToShell,
					Title:    "Command piped directly to shell",
					Description: fmt.Sprintf(
						"Step %q in job %q runs a network request and pipes the output directly to a shell. "+
							"This is insecure because the remote script could be modified in transit or hijacked, leading to arbitrary execution of arbitrary code.",
						stepName(&step), jobWrap.ID,
					),
					Recommendation: "Download the script to a file first, verify its SHA256 checksum against a known good value, and then execute it, or use a pinned official GitHub action instead.",
				})
			}
		}
	}
	return findings
}

// CheckMissingTimeout checks if jobs have defined timeout-minutes to prevent resource exhaustion.
func CheckMissingTimeout(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding
	for _, jobWrap := range jobs {
		if jobWrap.Node.TimeoutMinutes.Kind == 0 {
			findings = append(findings, Finding{
				File:     file,
				Line:     jobWrap.Line,
				Column:   jobWrap.Column,
				Severity: SeverityLow,
				Category: "BEST-PRAC-2",
				RuleID:   RuleMissingTimeout,
				Title:    "Job Timeout Not Configured",
				Description: fmt.Sprintf(
					"Job %q does not define a 'timeout-minutes' value. "+
						"By default, GitHub Actions jobs can run for up to 6 hours, which can cause excessive billing or hang resources in case of stuck steps.",
					jobWrap.ID,
				),
				Recommendation: "Define 'timeout-minutes' at the job level (e.g. 'timeout-minutes: 30' or another reasonable duration).",
			})
		}
	}
	return findings
}

// CheckSelfHostedRunners checks if jobs run on self-hosted runners which may expose internal environments.
func CheckSelfHostedRunners(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding
	for _, jobWrap := range jobs {
		runsOn := jobWrap.Node.RunsOn
		isSelfHosted := false

		if runsOn.Kind == yaml.ScalarNode {
			if runsOn.Value == "self-hosted" {
				isSelfHosted = true
			}
		} else if runsOn.Kind == yaml.SequenceNode {
			for _, item := range runsOn.Content {
				if item.Value == "self-hosted" {
					isSelfHosted = true
					break
				}
			}
		}

		if isSelfHosted {
			findings = append(findings, Finding{
				File:     file,
				Line:     runsOn.Line,
				Column:   runsOn.Column,
				Severity: SeverityLow,
				Category: "BEST-PRAC-3",
				RuleID:   RuleSelfHostedRunners,
				Title:    "Self-Hosted Runner Usage",
				Description: fmt.Sprintf(
					"Job %q is configured to run on a self-hosted runner. "+
						"Self-hosted runners can execute arbitrary code on internal infrastructure, which can be dangerous if the repo accepts public pull requests.",
					jobWrap.ID,
				),
				Recommendation: "Ensure the self-hosted runner is securely isolated, runs in a ephemeral/one-off container, and has restricted access to your network.",
			})
		}
	}
	return findings
}
