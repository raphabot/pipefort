package scanner

import "sort"

// The shipped combination catalog, described independently of any scan.
//
// DetectToxicCombinations answers "what chains exist in THIS repository". It
// cannot answer "what chains did we look for", because a combination that
// matched nothing simply produces no output — and a caller holding an empty
// result cannot tell an exhaustive search that found nothing from a search
// that was never run. A UI that renders only detections therefore says
// "no attack paths" in exactly the same way whether it checked thirteen
// scenarios or zero.
//
// ComboCatalog exports the denominator. It is deliberately a projection rather
// than the internal comboDef: comboDef carries stage templates and scope
// machinery that only the matcher needs, and pinning those into an exported
// type would freeze the matcher's internals as public API.

// ComboSpec is one shipped toxic combination as described to a consumer, with
// no reference to whether anything matched it.
type ComboSpec struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Severity ComboSeverity `json:"severity"`
	Scope    ComboScope    `json:"scope"`
	// Platform is derived from the combination's mandatory ingredients rather
	// than declared, so it cannot drift from the rules it is built out of. A
	// combination whose ingredients are all portable reports PlatformAny.
	Platform       Platform `json:"platform,omitempty"`
	Impact         string   `json:"impact"`
	BreakChain     string   `json:"break_chain"`
	BreakChainRule RuleID   `json:"break_chain_rule"`
	// Requirements is an AND of ORs: every group must be satisfied, and any one
	// rule within a group satisfies it. This shape (rather than a flat rule
	// list) is what lets a caller decide whether disabling a rule has made the
	// whole combination undetectable — see ComboCanFire.
	Requirements [][]RuleID `json:"requirements"`
	// Optional rules amplify a chain but are never needed to form one.
	Optional []RuleID `json:"optional"`
}

// ComboCatalog returns every shipped toxic combination, in the catalog's own
// order (the order DetectToxicCombinations evaluates them in).
func ComboCatalog() []ComboSpec {
	defs := comboCatalog()
	byRule := RuleByID()
	out := make([]ComboSpec, 0, len(defs))
	for _, d := range defs {
		spec := ComboSpec{
			ID:             d.id,
			Title:          d.title,
			Severity:       d.severity,
			Scope:          ScopeRepo,
			Impact:         d.impact,
			BreakChain:     d.breakChain,
			BreakChainRule: d.breakChainRule,
			Requirements:   make([][]RuleID, 0, len(d.required)),
			Optional:       make([]RuleID, 0, len(d.optional)),
		}
		if d.fileKeyed() {
			spec.Scope = ScopeFile
		}
		for _, req := range d.required {
			group := make([]RuleID, 0, len(req.anyOf))
			for _, ref := range req.anyOf {
				group = append(group, ref.rule)
			}
			spec.Requirements = append(spec.Requirements, group)
		}
		for _, ref := range d.optional {
			spec.Optional = append(spec.Optional, ref.rule)
		}
		spec.Platform = comboPlatform(spec.Requirements, byRule)
		out = append(out, spec)
	}
	return out
}

// ComboByID looks up one shipped combination.
func ComboByID(id string) (ComboSpec, bool) {
	for _, c := range ComboCatalog() {
		if c.ID == id {
			return c, true
		}
	}
	return ComboSpec{}, false
}

// ComboRules returns every rule that can take part in the combination —
// mandatory alternatives and optional amplifiers alike — deduplicated and
// sorted. Useful for "which rules would I have to keep on to keep looking for
// this", which is a different question from ComboCanFire's yes/no.
func ComboRules(spec ComboSpec) []RuleID {
	seen := map[RuleID]bool{}
	out := make([]RuleID, 0, len(spec.Optional))
	add := func(r RuleID) {
		if r == "" || seen[r] {
			return
		}
		seen[r] = true
		out = append(out, r)
	}
	for _, group := range spec.Requirements {
		for _, r := range group {
			add(r)
		}
	}
	for _, r := range spec.Optional {
		add(r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ComboCanFire reports whether the combination could still be detected with
// the given rules disabled.
//
// This is the difference between "we looked and found nothing" and "we were
// not looking". DetectToxicCombinations is documented to take findings that
// have ALREADY been rule-filtered, so a disabled ingredient silently removes
// its combination from the results — indistinguishable, downstream, from a
// clean repository. A caller that wants to report the distinction has to ask
// this before interpreting an absence.
//
// Only mandatory requirements count: an optional amplifier being off changes
// how a chain is described, never whether it forms.
func ComboCanFire(spec ComboSpec, disabled map[RuleID]bool) bool {
	if len(disabled) == 0 {
		return true
	}
	for _, group := range spec.Requirements {
		alive := false
		for _, r := range group {
			if !disabled[r] {
				alive = true
				break
			}
		}
		if !alive {
			return false
		}
	}
	return true
}

// comboPlatform derives which CI platform a combination belongs to from the
// rules that must be present to form it.
//
// Derived rather than declared because a combination IS its ingredients: a
// hand-maintained platform field on comboDef would be a second source of truth
// that nothing forces anyone to update when the ingredients change.
//
// A single GitLab ingredient decides it, because a mandatory GitLab rule makes
// the whole chain unreachable anywhere else. Everything else reads as GitHub,
// per Platform's own documented default — an untagged rule predates
// multi-provider support and parses GitHub Actions YAML or GitHub repository
// settings, so a chain built only from untagged rules can only form there.
// This deliberately never returns PlatformAny: no shipped combination is
// reachable on both, and a "portable" answer would invite callers to show a
// GitLab chain to a GitHub-only org.
func comboPlatform(requirements [][]RuleID, byRule map[RuleID]RuleSpec) Platform {
	for _, group := range requirements {
		for _, r := range group {
			if byRule[r].Platform == PlatformGitLab {
				return PlatformGitLab
			}
		}
	}
	return PlatformGitHub
}
