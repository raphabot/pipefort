package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CICD-SEC-1 — the two shapes of trigger-boundary confusion around
// pull_request_target.
//
// The trigger names differ by one word and the security models are opposites.
// `pull_request` runs the fork's code with no secrets and a read-only token.
// `pull_request_target` runs the BASE branch's workflow definition, with
// repository secrets and a write token, on an event about untrusted code.
// `workflow_run` is the same bargain in a different wrapper.
//
// Two findings come out of that:
//
//  1. A workflow bound to BOTH triggers. Every job then runs twice under two
//     different security models, and a reader has to hold both in their head to
//     reason about any one job. The usual history is someone adding
//     pull_request_target to make secrets available and forgetting to remove
//     the original — at which point the privileged copy is the one that
//     matters and nobody is looking at it.
//  2. A privileged-trigger job READING github.event.pull_request.head.* (or
//     the workflow_run equivalent). That is the bridge: attacker-controlled
//     head content meeting a token with write scope and repository secrets.
//
// (2) is deliberately broader than cicd-sec-1-ppe-checkout, which fires only on
// `actions/checkout` with an untrusted `ref:`. Head content reaches a job
// through an `if:` guard, another action's `with:` input, or a job `env:` just
// as well, and none of those are checkouts. One finding per job: it is one
// bridge to close, not one per mention.

// headContextRe matches a read of attacker-controlled head content. Both
// spellings: the pull_request event's nested head object, and workflow_run's
// flattened head_* fields.
var headContextRe = regexp.MustCompile(`(?i)github\s*\.\s*event\s*\.\s*(?:pull_request\s*\.\s*head\b|workflow_run\s*\.\s*head_(?:sha|ref|branch|commit|repository)\b)`)

// CheckPRTargetDualTrigger flags the pull_request + pull_request_target pair
// and privileged-trigger jobs that read untrusted head context.
func CheckPRTargetDualTrigger(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	if line, col, ok := dualTriggerAnchor(workflow); ok {
		findings = append(findings, Finding{
			File:     file,
			Line:     line,
			Column:   col,
			Severity: SeverityMedium,
			Category: "CICD-SEC-1",
			RuleID:   RulePRTargetDualTrigger,
			Title:    "Workflow is bound to both pull_request and pull_request_target triggers",
			Description: "The workflow runs on both pull_request and pull_request_target. The two triggers differ by one word and have opposite security models: pull_request runs the fork's code with a read-only token and no secrets, while pull_request_target runs the base branch's workflow definition with repository secrets and a write token. " +
				"Bound to both, every job runs twice under two different models, and the privileged copy is the one an attacker targets.",
			Recommendation: "Keep one trigger. Use pull_request for anything that builds or tests contributor code. If a job genuinely needs secrets on a fork PR, move just that job into a separate pull_request_target workflow that does not check out or execute head content, and gate it on a label or an approving review.",
		})
	}

	// The head-context half only matters under a privileged trigger — the same
	// read under a plain pull_request has no secrets or write token to reach.
	if !onTriggers(workflow, "pull_request_target", "workflow_run") {
		return findings
	}

	for _, jobWrap := range jobs {
		j := jobWrap
		node, ok := firstHeadContextNode(j)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			File:     file,
			Line:     node.Line,
			Column:   node.Column,
			Severity: SeverityHigh,
			Category: "CICD-SEC-1",
			RuleID:   RulePRTargetDualTrigger,
			Title:    "Privileged-trigger job reads untrusted pull-request head context",
			Description: fmt.Sprintf(
				"Job %q runs on a privileged trigger (pull_request_target or workflow_run) and reads github.event.…head.…, which is content the pull-request author controls. "+
					"The job holds repository secrets and a write-scoped token, so this is the point where attacker-controlled input meets privilege — the classic pwn-request bridge.",
				j.ID,
			),
			Recommendation: "Do not let head content influence a privileged job. Read the head ref only to post a comment or set a status; never to check out, build, execute, or interpolate into a shell. If the job must act on the PR's code, split that work into a pull_request-triggered workflow that has no secrets.",
		})
	}
	return findings
}

// dualTriggerAnchor reports whether the workflow declares both triggers, and
// where to anchor the finding — the pull_request_target entry, since that is
// the one to remove.
func dualTriggerAnchor(workflow *WorkflowNode) (line, col int, ok bool) {
	on := workflow.On
	var hasPR, hasPRT bool
	var anchor *yaml.Node

	mark := func(n *yaml.Node) {
		switch n.Value {
		case "pull_request":
			hasPR = true
		case "pull_request_target":
			hasPRT = true
			anchor = n
		}
	}

	switch on.Kind {
	case yaml.SequenceNode:
		for _, it := range on.Content {
			mark(it)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			mark(on.Content[i])
		}
	}
	if !hasPR || !hasPRT || anchor == nil {
		return 0, 0, false
	}
	return anchor.Line, anchor.Column, true
}

// firstHeadContextNode returns the first node in a job that reads head
// context, searching the places head content actually reaches a job: the job's
// own `if:` and `env:`, and each step's `if:`, `with:`, `env:`, and `run:`.
func firstHeadContextNode(j JobNodeWithID) (*yaml.Node, bool) {
	candidates := []*yaml.Node{&j.Node.If, &j.Node.Env}
	for _, step := range decodeSteps(j.Node) {
		s := step
		candidates = append(candidates, &s.If, &s.With, &s.Env, &s.Run)
	}
	for _, n := range candidates {
		if n == nil || n.Kind == 0 {
			continue
		}
		if headContextRe.MatchString(nodeText(n)) {
			return n, true
		}
	}
	return nil, false
}

// --- Auto-fix (partial) -----------------------------------------------------

// prTargetFixMarker tags a comment this fixer wrote, so a second pass
// recognises its own work.
const prTargetFixMarker = "pipefort: pull_request_target trigger"

// fixPRTargetDualTrigger annotates the trigger block.
//
// Partial by necessity. Dropping pull_request_target changes which secrets the
// workflow can see; dropping pull_request changes when it runs at all; and
// splitting the file is a refactor, not a rewrite. Any of those could silently
// break a release path, so the fix marks the trigger that needs the decision
// and leaves the decision to a human. The head-context half gets no fix at all
// — there is nothing mechanical to do about a job reading untrusted input.
func fixPRTargetDualTrigger(rootNode *yaml.Node, f Finding) bool {
	// Only the dual-trigger finding is anchored inside the `on:` block.
	_, onNode, _ := findMapKey(rootNode, "on")
	if onNode == nil {
		return false
	}
	target := nodeAtPosition(onNode, f.Line, f.Column)
	if target == nil {
		return false
	}
	if strings.Contains(target.HeadComment, prTargetFixMarker) {
		return false
	}
	comment := fmt.Sprintf("%s — %s\n%s", prTargetFixMarker, f.Title, f.Recommendation)
	if target.HeadComment != "" {
		comment = target.HeadComment + "\n" + comment
	}
	target.HeadComment = comment
	return true
}

// nodeAtPosition finds the node at an exact line/column within a subtree.
func nodeAtPosition(root *yaml.Node, line, col int) *yaml.Node {
	if root == nil {
		return nil
	}
	if root.Line == line && root.Column == col {
		return root
	}
	for _, child := range root.Content {
		if n := nodeAtPosition(child, line, col); n != nil {
			return n
		}
	}
	return nil
}
