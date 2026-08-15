package scanner

import "testing"

// The catalog is the denominator behind "we looked for N chains and found M",
// so the tests that matter are the ones that would catch it drifting away from
// what DetectToxicCombinations actually evaluates.

func TestComboCatalogCoversEveryDetectableCombination(t *testing.T) {
	specs := ComboCatalog()
	defs := comboCatalog()
	if len(specs) != len(defs) {
		t.Fatalf("catalog exports %d combinations, matcher evaluates %d", len(specs), len(defs))
	}
	for i, d := range defs {
		if specs[i].ID != d.id {
			t.Errorf("position %d: exported %q, matcher has %q", i, specs[i].ID, d.id)
		}
	}
	seen := map[string]bool{}
	for _, s := range specs {
		if seen[s.ID] {
			t.Errorf("duplicate combination id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Title == "" || s.Impact == "" || s.BreakChain == "" {
			t.Errorf("%s: a combination shown without a detection must still be able to explain itself", s.ID)
		}
		if len(s.Requirements) == 0 {
			t.Errorf("%s: no requirements, so nothing could ever satisfy it", s.ID)
		}
	}
}

func TestComboCatalogRequirementsNameRealRules(t *testing.T) {
	byRule := RuleByID()
	for _, s := range ComboCatalog() {
		for _, r := range ComboRules(s) {
			if _, ok := byRule[r]; !ok {
				t.Errorf("%s: ingredient %q is not in the rule catalog", s.ID, r)
			}
		}
		if s.BreakChainRule != "" {
			if _, ok := byRule[s.BreakChainRule]; !ok {
				t.Errorf("%s: break-chain rule %q is not in the rule catalog", s.ID, s.BreakChainRule)
			}
		}
	}
}

func TestComboCatalogPlatformSplitsGitLabFromGitHub(t *testing.T) {
	for _, s := range ComboCatalog() {
		if s.Platform != PlatformGitHub && s.Platform != PlatformGitLab {
			t.Errorf("%s: platform %q — a combination must belong to exactly one platform, or a GitHub-only org will be shown GitLab chains", s.ID, s.Platform)
		}
	}
	gl, ok := ComboByID("gl-pwn-request")
	if !ok {
		t.Fatal("gl-pwn-request missing from the catalog")
	}
	if gl.Platform != PlatformGitLab {
		t.Errorf("gl-pwn-request platform = %q, want gitlab", gl.Platform)
	}
	gh, ok := ComboByID("pwn-request")
	if !ok {
		t.Fatal("pwn-request missing from the catalog")
	}
	if gh.Platform != PlatformGitHub {
		t.Errorf("pwn-request platform = %q, want github", gh.Platform)
	}
}

func TestComboCanFireDistinguishesQuietFromBlind(t *testing.T) {
	spec, ok := ComboByID("pwn-request")
	if !ok {
		t.Fatal("pwn-request missing from the catalog")
	}

	if !ComboCanFire(spec, nil) {
		t.Error("nothing disabled should leave every combination detectable")
	}

	// The anchor requirement is a single rule, so turning it off blinds the
	// whole chain — an empty result then means "not looking", not "clean".
	if ComboCanFire(spec, map[RuleID]bool{RulePPECheckout: true}) {
		t.Error("disabling the only rule in a requirement should make the combination undetectable")
	}

	// The token requirement is an OR group. One alternative off still leaves
	// the chain findable through the other, so the absence is still meaningful.
	if !ComboCanFire(spec, map[RuleID]bool{RuleMissingPermissions: true}) {
		t.Error("an OR group keeps firing while any alternative is enabled")
	}
	if ComboCanFire(spec, map[RuleID]bool{RuleMissingPermissions: true, RuleWPermWrite: true}) {
		t.Error("disabling every alternative in a group should make the combination undetectable")
	}

	// Optional amplifiers change how a chain reads, never whether it forms.
	if !ComboCanFire(spec, map[RuleID]bool{RulePPEShellInjection: true}) {
		t.Error("an optional ingredient must not gate detectability")
	}
}

// A combination the catalog says can fire must actually be produced by the
// matcher when its ingredients are present — otherwise the two halves of the
// page disagree about the same repository.
func TestComboCatalogAgreesWithTheMatcher(t *testing.T) {
	findings := []Finding{
		{RuleID: RulePPECheckout, File: ".github/workflows/ci.yml", Line: 3},
		{RuleID: RuleMissingPermissions, File: ".github/workflows/ci.yml", Line: 9},
	}
	spec, _ := ComboByID("pwn-request")
	if !ComboCanFire(spec, nil) {
		t.Fatal("precondition: pwn-request should be detectable with nothing disabled")
	}

	got := DetectToxicCombinations(findings)
	found := false
	for _, c := range got {
		if c.ID == "pwn-request" {
			found = true
		}
	}
	if !found {
		t.Fatal("catalog claims pwn-request is detectable, matcher did not detect it from its own ingredients")
	}

	// And with the anchor disabled, the caller filters first and the matcher
	// produces nothing — which is precisely the case ComboCanFire exists to
	// let the caller narrate.
	filtered := FilterByEnabledRules(findings, map[RuleID]bool{RulePPECheckout: true})
	if len(DetectToxicCombinations(filtered)) != 0 {
		t.Error("filtering out the anchor should leave no combination")
	}
	if ComboCanFire(spec, map[RuleID]bool{RulePPECheckout: true}) {
		t.Error("...and the catalog should say so, rather than letting the empty result read as clean")
	}
}
