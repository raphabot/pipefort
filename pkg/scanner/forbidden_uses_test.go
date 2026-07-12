package scanner

import "testing"

func refsFrom(t *testing.T, wf string) []ActionRef {
	t.Helper()
	return CollectActionRefsFromBytes(".github/workflows/ci.yml", []byte(wf))
}

const forbiddenWF = `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sketchy-org/thing@v1
      - uses: docker/login-action@v3
`

func TestForbiddenUsesNilPolicyIsSilent(t *testing.T) {
	if got := CheckForbiddenUses(refsFrom(t, forbiddenWF), nil); got != nil {
		t.Errorf("nil policy should be silent, got %d findings", len(got))
	}
	empty := &ForbiddenUses{}
	if got := CheckForbiddenUses(refsFrom(t, forbiddenWF), empty); got != nil {
		t.Errorf("empty policy should be silent, got %d findings", len(got))
	}
}

func TestForbiddenUsesDenyList(t *testing.T) {
	policy := &ForbiddenUses{Deny: []string{"sketchy-org/*"}}
	got := CheckForbiddenUses(refsFrom(t, forbiddenWF), policy)
	if len(got) != 1 {
		t.Fatalf("expected 1 deny finding, got %d", len(got))
	}
	if got[0].RuleID != RuleForbiddenUses {
		t.Errorf("unexpected rule id %q", got[0].RuleID)
	}
}

func TestForbiddenUsesAllowList(t *testing.T) {
	// Only actions/* and docker/* are allowed → sketchy-org/thing is flagged.
	policy := &ForbiddenUses{Allow: []string{"actions/*", "docker/*"}}
	got := CheckForbiddenUses(refsFrom(t, forbiddenWF), policy)
	if len(got) != 1 {
		t.Fatalf("expected 1 allow-list violation, got %d: %+v", len(got), got)
	}
}

func TestForbiddenUsesOwnerOnlyPattern(t *testing.T) {
	// A bare owner pattern matches the whole namespace.
	policy := &ForbiddenUses{Deny: []string{"docker"}}
	got := CheckForbiddenUses(refsFrom(t, forbiddenWF), policy)
	if len(got) != 1 {
		t.Fatalf("expected docker/* to be denied, got %d", len(got))
	}
}
