package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CICD-SEC-8 — a sensitive job on a self-hosted runner with nothing declared
// about where that runner may talk to.
//
// A GitHub-hosted runner is a fresh VM that is destroyed after the job. A
// self-hosted runner is a machine on somebody's network, and by default it can
// reach the whole internet with the job's secrets in scope. That is the shape
// exfiltration takes when it does not need an exploit: the job legitimately
// holds a deploy key and legitimately makes network calls, and nothing
// distinguishes the call that ships the build from the call that ships the key.
//
// Self-hosted alone is not a finding — best-prac-3 already reports the fact,
// tiered to the auditor persona because it is usually a deliberate infra
// choice. This rule fires only where the combination bites: a self-hosted
// runner AND something worth stealing. Three sensitive traits, any one of which
// is enough:
//
//   - the job consumes secrets,
//   - the workflow runs on pull_request_target (untrusted input, privileged
//     context, on your own hardware),
//   - the job publishes a release or package.
//
// Advisory, and there is no auto-fix. Egress control lives in runner
// infrastructure — a firewall, a network policy, a proxy — not in the workflow
// file. The scanner cannot see that infrastructure, which is why the rule
// carries its own acknowledgment surface (below) rather than guessing.

// egressAckDirective is the comment a team writes to say "egress on this
// runner is governed elsewhere". Placed on a job it covers that job; placed at
// the top of the file it covers every job in it.
//
// A dedicated directive rather than the generic `# pipefort: ignore[...]`
// because the two mean different things. `ignore` says "do not tell me about
// this"; `egress-restricted` says "this is handled, here is the claim on the
// record" — and it reads that way to the next person in the diff.
var egressAckDirective = regexp.MustCompile(`#\s*pipefort:\s*egress-restricted\b`)

// hardenRunnerAction is the one marketplace action that declares an egress
// policy inside the workflow file, so it is the one signal this rule can read
// without leaving the YAML.
const hardenRunnerAction = "step-security/harden-runner"

// publishActionRe matches actions whose purpose is publishing a release or
// package — the artifact half of "something worth stealing".
var publishActionRe = regexp.MustCompile(`(?i)^(softprops/action-gh-release|actions/create-release|ncipollo/release-action|pypa/gh-action-pypi-publish|JS-DevTools/npm-publish|docker/build-push-action|goreleaser/goreleaser-action|gradle/gradle-publish|release-drafter/release-drafter)`)

// publishCmdRe matches the same intent expressed as a shell command.
var publishCmdRe = regexp.MustCompile(`(?i)\b(npm\s+publish|yarn\s+publish|pnpm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push|mvn\s+deploy|gradle\s+publish|docker\s+push|helm\s+push|gh\s+release\s+create|goreleaser\s+release)\b`)

// secretsUseRe matches a reference to the secrets context in any of the places
// a job reads one.
var secretsUseRe = regexp.MustCompile(`(?i)\bsecrets\s*[.\[]`)

// CheckSelfHostedEgress flags sensitive jobs on self-hosted runners with no
// declared egress control.
func CheckSelfHostedEgress(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	prTarget := onTriggers(workflow, "pull_request_target")
	jobComments := jobKeyComments(workflow)

	var findings []Finding
	for _, jobWrap := range jobs {
		j := jobWrap
		if !isSelfHostedRunner(&j.Node.RunsOn) {
			continue
		}
		if egressAckDirective.MatchString(jobComments[j.ID]) {
			continue
		}

		reason, ok := sensitiveJobTrait(j, prTarget)
		if !ok {
			continue
		}

		policy, hasHardenRunner := hardenRunnerEgressPolicy(j)
		if hasHardenRunner && strings.EqualFold(policy, "block") {
			continue
		}

		declared := "no egress policy is declared in the workflow"
		if hasHardenRunner {
			declared = fmt.Sprintf("the job runs %s with egress-policy: %s, which observes egress but does not restrict it", hardenRunnerAction, policy)
		}

		findings = append(findings, Finding{
			File:     file,
			Line:     j.Node.RunsOn.Line,
			Column:   j.Node.RunsOn.Column,
			Severity: SeverityMedium,
			Category: "CICD-SEC-8",
			RuleID:   RuleSelfHostedEgress,
			Title:    "Sensitive job on a self-hosted runner with no declared egress restriction",
			Description: fmt.Sprintf(
				"Job %q runs on a self-hosted runner and %s, and %s. "+
					"A self-hosted runner is a machine on your network that can reach the whole internet by default, so nothing distinguishes the call that ships the build from the call that ships the credential.",
				j.ID, reason, declared,
			),
			Recommendation: "Restrict what the runner may reach: an egress allowlist at the firewall or network policy, or `step-security/harden-runner` with `egress-policy: block` and an `allowed-endpoints:` list. If egress is already governed outside this repository, record it with a `# pipefort: egress-restricted` comment on the job (or at the top of the file for every job).",
			Confidence:     ConfidenceMedium,
		})
	}
	return findings
}

// isSelfHostedRunner reports whether a runs-on targets a self-hosted runner,
// in the scalar, label-list, or runner-group form.
func isSelfHostedRunner(runsOn *yaml.Node) bool {
	if runsOn == nil {
		return false
	}
	switch runsOn.Kind {
	case yaml.ScalarNode:
		return strings.EqualFold(strings.TrimSpace(runsOn.Value), "self-hosted")
	case yaml.SequenceNode:
		for _, it := range runsOn.Content {
			if strings.EqualFold(strings.TrimSpace(it.Value), "self-hosted") {
				return true
			}
		}
	case yaml.MappingNode:
		// `runs-on: { group: my-runners }` — a runner group is by definition
		// self-hosted; GitHub-hosted runners are addressed by label.
		return mappingValueByKey(runsOn, "group") != nil
	}
	return false
}

// sensitiveJobTrait returns the reason a job is worth protecting, and whether
// it has one at all.
func sensitiveJobTrait(j JobNodeWithID, prTarget bool) (string, bool) {
	if prTarget {
		return "the workflow is triggered by pull_request_target, so untrusted pull-request content reaches a privileged job on your own hardware", true
	}

	steps := decodeSteps(j.Node)

	// Publishing: an action whose job is to publish, or the shell equivalent.
	for _, step := range steps {
		s := step
		if s.Uses.Value != "" && publishActionRe.MatchString(actionRepo(s.Uses.Value)) {
			return fmt.Sprintf("publishes a release or package (%s)", actionRepo(s.Uses.Value)), true
		}
		if s.Run.Value != "" {
			if m := publishCmdRe.FindString(s.Run.Value); m != "" {
				return fmt.Sprintf("publishes a release or package (`%s`)", strings.Join(strings.Fields(m), " ")), true
			}
		}
	}

	// Secrets: the job env, or any step's env/with/run/if.
	if secretsUseRe.MatchString(nodeText(&j.Node.Env)) {
		return "consumes repository secrets", true
	}
	for _, step := range steps {
		s := step
		for _, n := range []*yaml.Node{&s.Env, &s.With, &s.Run, &s.If} {
			if secretsUseRe.MatchString(nodeText(n)) {
				return "consumes repository secrets", true
			}
		}
	}
	return "", false
}

// hardenRunnerEgressPolicy returns the egress-policy a harden-runner step
// declares, and whether the job runs harden-runner at all. An absent `with:`
// leaves the policy empty, which harden-runner treats as audit.
func hardenRunnerEgressPolicy(j JobNodeWithID) (string, bool) {
	for _, step := range decodeSteps(j.Node) {
		s := step
		if s.Uses.Value == "" || actionRepo(s.Uses.Value) != hardenRunnerAction {
			continue
		}
		policy := "audit"
		if v := mappingValueByKey(&s.With, "egress-policy"); v != nil && strings.TrimSpace(v.Value) != "" {
			policy = strings.TrimSpace(v.Value)
		}
		return policy, true
	}
	return "", false
}

// jobKeyComments returns every comment attached to a job's key node, keyed by
// job ID. Comments survive the parse, which is what lets the acknowledgment
// live in the file next to the thing it describes.
func jobKeyComments(workflow *WorkflowNode) map[string]string {
	out := map[string]string{}
	if workflow.Jobs.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(workflow.Jobs.Content); i += 2 {
		k := workflow.Jobs.Content[i]
		out[k.Value] = k.HeadComment + "\n" + k.LineComment + "\n" + k.FootComment
	}
	return out
}

// fileEgressAckRe matches the FILE-level acknowledgment: the directive as a
// standalone comment at zero indentation. Nesting is the scope: an indented
// directive belongs to the job it sits above, an unindented one to the file.
//
// Read off the raw bytes rather than the tree because a comment before the
// document's first key attaches to that KEY node, and decoding a mapping into
// a struct keeps only the value nodes — so by the time a check sees a
// WorkflowNode, a file-leading comment is gone. applyInlineIgnores has the
// same constraint and solves it the same way.
var fileEgressAckRe = regexp.MustCompile(`(?m)^#\s*pipefort:\s*egress-restricted\b`)

// dropFileLevelEgressAck removes every self-hosted-egress finding when the
// file carries a file-level acknowledgment. Applied in ScanBytes so the CLI,
// the web scanner, and the fixers' re-scan all honour it.
func dropFileLevelEgressAck(findings []Finding, content []byte) []Finding {
	if !fileEgressAckRe.Match(content) {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == RuleSelfHostedEgress {
			continue
		}
		out = append(out, f)
	}
	return out
}

// --- GitLab CI --------------------------------------------------------------

// checkGitLabSelfHostedEgress is the portable half. GitLab has no `self-hosted`
// label: a job reaches a specific runner through `tags:`, so a tag that is not
// one of GitLab's SaaS runner names means somebody's own machine.
func checkGitLabSelfHostedEgress(file string, jobs []glJob) []Finding {
	var findings []Finding
	for _, job := range jobs {
		j := job
		tags := selfHostedGitLabTags(j)
		if len(tags) == 0 {
			continue
		}
		if j.Key != nil && egressAckDirective.MatchString(j.Key.HeadComment+"\n"+j.Key.LineComment) {
			continue
		}
		reason, ok := sensitiveGitLabJobTrait(j)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     j.Tags.Line,
			Column:   j.Tags.Column,
			Severity: SeverityMedium,
			Category: "CICD-SEC-8",
			RuleID:   RuleSelfHostedEgress,
			Title:    "Sensitive job on a self-hosted runner with no declared egress restriction",
			Description: fmt.Sprintf(
				"Job %q targets self-hosted runner tags %v and %s, with no egress policy declared. "+
					"A self-hosted runner is a machine on your network that can reach the whole internet by default, so nothing distinguishes the call that ships the build from the call that ships the credential.",
				j.ID, tags, reason,
			),
			Recommendation: "Restrict what the runner may reach with an egress allowlist at the firewall or network policy, or move the job to a `saas-*` shared runner. If egress is already governed outside this repository, record it with a `# pipefort: egress-restricted` comment on the job (or at the top of the file for every job).",
			Confidence:     ConfidenceMedium,
		})
	}
	return findings
}

// selfHostedGitLabTags returns the job's non-SaaS runner tags.
func selfHostedGitLabTags(j glJob) []string {
	if j.Tags == nil || j.Tags.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, t := range j.Tags.Content {
		if t.Kind != yaml.ScalarNode || saasRunnerTagRe.MatchString(t.Value) {
			continue
		}
		out = append(out, t.Value)
	}
	return out
}

// sensitiveGitLabJobTrait mirrors the GitHub trait test. GitLab has no secrets
// context, so a credential shows up as a CI/CD variable reference — the
// CI_*_TOKEN family plus any variable whose name reads like a credential.
func sensitiveGitLabJobTrait(j glJob) (string, bool) {
	for _, line := range allScripts(j) {
		if m := publishCmdRe.FindString(line.Text); m != "" {
			return fmt.Sprintf("publishes a release or package (`%s`)", strings.Join(strings.Fields(m), " ")), true
		}
	}
	body := nodeText(j.Vars)
	for _, line := range allScripts(j) {
		body += "\n" + line.Text
	}
	if glCredentialVarRe.MatchString(body) {
		return "consumes CI/CD credential variables", true
	}
	return "", false
}

// glCredentialVarRe matches a GitLab variable reference that carries a
// credential: the CI_*_TOKEN family GitLab injects, or a name ending in the
// usual credential words.
var glCredentialVarRe = regexp.MustCompile(`(?i)\$\{?(CI_[A-Z0-9_]*(TOKEN|PASSWORD|KEY)|[A-Z0-9_]*(_TOKEN|_PASSWORD|_SECRET|_API_KEY|_ACCESS_KEY))\b`)
