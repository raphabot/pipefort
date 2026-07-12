package scanner

import (
	"fmt"
	"strings"
)

// popularActions is a bundled allowlist of widely-used actions. Typosquat
// detection flags a reference that is one edit away from one of these but not an
// exact match — the classic "actons/checkout" attack. Kept deliberately small
// and high-traffic to minimize false positives; extend as needed.
var popularActions = []string{
	"actions/checkout",
	"actions/setup-node",
	"actions/setup-python",
	"actions/setup-go",
	"actions/setup-java",
	"actions/setup-dotnet",
	"actions/cache",
	"actions/upload-artifact",
	"actions/download-artifact",
	"actions/github-script",
	"actions/stale",
	"actions/labeler",
	"actions/configure-pages",
	"actions/deploy-pages",
	"actions/attest-build-provenance",
	"docker/build-push-action",
	"docker/login-action",
	"docker/setup-buildx-action",
	"docker/setup-qemu-action",
	"docker/metadata-action",
	"aws-actions/configure-aws-credentials",
	"azure/login",
	"google-github-actions/auth",
	"hashicorp/setup-terraform",
	"codecov/codecov-action",
	"softprops/action-gh-release",
	"peter-evans/create-pull-request",
	"github/codeql-action",
	"ruby/setup-ruby",
	"pnpm/action-setup",
}

// popularActionSet is the lowercased lookup set, built once.
var popularActionSet = func() map[string]bool {
	m := make(map[string]bool, len(popularActions))
	for _, a := range popularActions {
		m[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return m
}()

// checkTyposquat flags an action whose owner/repo is exactly one edit away from
// a popular action (and isn't itself a popular action). Returns nil otherwise.
func checkTyposquat(r ActionRef) *Finding {
	candidate := strings.ToLower(r.Owner + "/" + r.Repo)
	if popularActionSet[candidate] {
		return nil // it IS a known-good action
	}
	for _, known := range popularActions {
		known = strings.ToLower(strings.TrimSpace(known))
		if levenshtein(candidate, known) == 1 {
			return &Finding{
				File:     r.File,
				Line:     r.Line,
				Column:   r.Column,
				Severity: SeverityMedium,
				Category: "CICD-SEC-3",
				RuleID:   RuleTyposquatAction,
				Title:    "Possible typosquatted action",
				Description: fmt.Sprintf(
					"Action %q is one character away from the popular action %q. "+
						"An attacker who registers a near-identical name can trick workflows into running their code.",
					r.Owner+"/"+r.Repo, known),
				Recommendation: fmt.Sprintf("Confirm you intended %q and not %q. If correct, this is a false positive; if not, switch to the official action.", r.Owner+"/"+r.Repo, known),
			}
		}
	}
	return nil
}

// levenshtein returns the edit distance between two strings (single-row DP).
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur := make([]int, lb+1)
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
