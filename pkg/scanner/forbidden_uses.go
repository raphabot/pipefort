package scanner

import (
	"fmt"
	"path"
	"strings"
)

// CheckForbiddenUses enforces a repository's action allow/deny policy from its
// .pipefort.yml `forbidden-uses` block. It matches each action reference's
// `owner/repo` (ignoring the @ref) against the policy patterns (globs, e.g.
// `someorg/*` or `actions/checkout`). Allow and Deny are mutually exclusive;
// Allow wins when both are set. Returns nil when no policy is configured, so
// the rule is silent by default.
func CheckForbiddenUses(refs []ActionRef, policy *ForbiddenUses) []Finding {
	if policy == nil || (len(policy.Allow) == 0 && len(policy.Deny) == 0) {
		return nil
	}
	var findings []Finding
	for _, r := range refs {
		name := r.Owner + "/" + r.Repo
		var reason string
		switch {
		case len(policy.Allow) > 0:
			if !matchesAnyActionGlob(name, policy.Allow) {
				reason = fmt.Sprintf("%q is not on the forbidden-uses allow list", name)
			}
		default: // deny list
			if matchesAnyActionGlob(name, policy.Deny) {
				reason = fmt.Sprintf("%q matches the forbidden-uses deny list", name)
			}
		}
		if reason == "" {
			continue
		}
		findings = append(findings, Finding{
			File:     r.File,
			Line:     r.Line,
			Column:   r.Column,
			Severity: SeverityHigh,
			Category: "CICD-SEC-5",
			RuleID:   RuleForbiddenUses,
			Title:    "Action not permitted by forbidden-uses policy",
			Description: fmt.Sprintf(
				"Step uses action %q, which %s (configured in .pipefort.yml).",
				r.Raw, reason,
			),
			Recommendation: "Replace the action with one your policy permits, or update the forbidden-uses allow/deny list in .pipefort.yml if this action is intended.",
		})
	}
	return StampConfidence(findings)
}

// matchesAnyActionGlob reports whether an owner/repo name matches any of the
// glob patterns. A bare pattern with no slash (e.g. "someorg") matches that
// owner's whole namespace.
func matchesAnyActionGlob(name string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			p += "/*" // owner-only → whole namespace
		}
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}
