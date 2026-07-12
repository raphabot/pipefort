package scanner

import (
	"context"
	"testing"
)

// fakeAuditor is an in-memory PinAuditor for testing the audits with no network.
type fakeAuditor struct {
	// refs maps "owner/repo@ref" → resolved SHA. A missing key means "not found".
	refs map[string]string
	// advisories maps "owner/repo" → advisories.
	advisories map[string][]Advisory
	// archived maps "owner/repo" → archived flag (present = readable).
	archived map[string]bool
	// tags maps "owner/repo" → tag commit SHAs.
	tags map[string][]string
	// branchRefs / tagRefs are sets of "owner/repo@ref" that exist as a
	// branch / tag respectively (for ref-confusion).
	branchRefs map[string]bool
	tagRefs    map[string]bool
}

func (f *fakeAuditor) ResolveRef(_ context.Context, owner, repo, ref string) (string, bool, error) {
	sha, ok := f.refs[owner+"/"+repo+"@"+ref]
	return sha, ok, nil
}

func (f *fakeAuditor) Advisories(_ context.Context, owner, repo string) ([]Advisory, error) {
	return f.advisories[owner+"/"+repo], nil
}

func (f *fakeAuditor) RepoArchived(_ context.Context, owner, repo string) (bool, bool, error) {
	v, ok := f.archived[owner+"/"+repo]
	return v, ok, nil
}

func (f *fakeAuditor) RefKinds(_ context.Context, owner, repo, ref string) (bool, bool, error) {
	key := owner + "/" + repo + "@" + ref
	return f.branchRefs[key], f.tagRefs[key], nil
}

func (f *fakeAuditor) TagSHAs(_ context.Context, owner, repo string) ([]string, error) {
	return f.tags[owner+"/"+repo], nil
}

func auditYAML(t *testing.T, yaml string, auditor PinAuditor) []Finding {
	t.Helper()
	refs := CollectActionRefsFromBytes(".github/workflows/ci.yml", []byte(yaml))
	return AuditActionPins(context.Background(), refs, auditor)
}

func hasRule(findings []Finding, id RuleID) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestCollectActionRefs_CapturesVersionComment(t *testing.T) {
	// Guards the assumption that yaml.v3 preserves the uses: line comment through
	// the job/steps Decode path — ref-version-mismatch depends on it.
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111 # v4
      - uses: ./local-action
      - uses: docker://alpine:3.18
`
	refs := CollectActionRefsFromBytes(".github/workflows/ci.yml", []byte(yaml))
	if len(refs) != 1 {
		t.Fatalf("expected 1 third-party ref (local + docker skipped), got %d: %+v", len(refs), refs)
	}
	if refs[0].Owner != "actions" || refs[0].Repo != "checkout" {
		t.Errorf("unexpected ref %+v", refs[0])
	}
	if refs[0].VersionComment != "v4" {
		t.Errorf("VersionComment = %q, want v4 (comment not preserved through decode)", refs[0].VersionComment)
	}
}

func TestAudit_ImpostorCommit(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
`
	// SHA not present in the repo → impostor.
	got := auditYAML(t, yaml, &fakeAuditor{refs: map[string]string{}})
	if !hasRule(got, RuleImpostorCommit) {
		t.Errorf("expected impostor-commit finding, got %+v", got)
	}

	// SHA present → clean.
	sha := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	got = auditYAML(t, yaml, &fakeAuditor{refs: map[string]string{"actions/checkout@" + sha: sha}})
	if hasRule(got, RuleImpostorCommit) {
		t.Errorf("did not expect impostor finding when SHA exists: %+v", got)
	}
}

func TestAudit_RefVersionMismatch(t *testing.T) {
	pinned := "1111111111111111111111111111111111111111"
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + pinned + ` # v4
`
	// v4 tag resolves to a *different* SHA → mismatch.
	auditor := &fakeAuditor{refs: map[string]string{
		"actions/checkout@" + pinned: pinned, // the pin exists (not impostor)
		"actions/checkout@v4":        "2222222222222222222222222222222222222222",
	}}
	got := auditYAML(t, yaml, auditor)
	if !hasRule(got, RuleRefVersionMismatch) {
		t.Errorf("expected ref-version-mismatch, got %+v", got)
	}

	// v4 tag resolves to the same SHA → clean.
	auditor = &fakeAuditor{refs: map[string]string{
		"actions/checkout@" + pinned: pinned,
		"actions/checkout@v4":        pinned,
	}}
	got = auditYAML(t, yaml, auditor)
	if hasRule(got, RuleRefVersionMismatch) {
		t.Errorf("did not expect mismatch when tag matches pin: %+v", got)
	}
}

func TestAudit_KnownVulnerable(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@1.0.0
`
	auditor := &fakeAuditor{advisories: map[string][]Advisory{
		"some-org/some-action": {{GHSAID: "GHSA-xxxx", Summary: "RCE", VulnerableRange: "< 1.2.3", FirstPatched: "1.2.3"}},
	}}
	got := auditYAML(t, yaml, auditor)
	if !hasRule(got, RuleKnownVulnerableAction) {
		t.Errorf("expected known-vulnerable finding for 1.0.0 < 1.2.3, got %+v", got)
	}

	// A patched version is clean.
	yamlPatched := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@1.2.3
`
	got = auditYAML(t, yamlPatched, auditor)
	if hasRule(got, RuleKnownVulnerableAction) {
		t.Errorf("did not expect finding for patched 1.2.3: %+v", got)
	}
}

func TestAudit_Typosquat(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actons/checkout@v4
`
	got := auditYAML(t, yaml, &fakeAuditor{})
	if !hasRule(got, RuleTyposquatAction) {
		t.Errorf("expected typosquat finding for actons/checkout, got %+v", got)
	}

	// The real action is not flagged.
	yamlReal := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	got = auditYAML(t, yamlReal, &fakeAuditor{})
	if hasRule(got, RuleTyposquatAction) {
		t.Errorf("did not expect typosquat for the real action: %+v", got)
	}
}

func TestVersionInRange(t *testing.T) {
	cases := []struct {
		version, rng string
		want         bool
	}{
		{"1.0.0", "< 1.2.3", true},
		{"1.2.3", "< 1.2.3", false},
		{"1.2.3", "<= 1.2.3", true},
		{"1.1.0", ">= 1.0.0, < 1.2.0", true},
		{"1.3.0", ">= 1.0.0, < 1.2.0", false},
		{"v2.0.0", "= 2.0.0", true},
		{"2.0.0", "garbage", false},
		{"not-semver", "< 1.0.0", false},
	}
	for _, c := range cases {
		if got := versionInRange(c.version, c.rng); got != c.want {
			t.Errorf("versionInRange(%q, %q) = %v, want %v", c.version, c.rng, got, c.want)
		}
	}
}

func TestAudit_ArchivedAction(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: oldorg/deadaction@v1
`
	got := auditYAML(t, yaml, &fakeAuditor{archived: map[string]bool{"oldorg/deadaction": true}})
	if !hasRule(got, RuleArchivedAction) {
		t.Errorf("expected archived-action finding, got %+v", got)
	}

	// Not archived → clean.
	got = auditYAML(t, yaml, &fakeAuditor{archived: map[string]bool{"oldorg/deadaction": false}})
	if hasRule(got, RuleArchivedAction) {
		t.Errorf("did not expect archived finding for a live repo: %+v", got)
	}

	// Repo unreadable (absent from map → ok=false) → no finding.
	got = auditYAML(t, yaml, &fakeAuditor{})
	if hasRule(got, RuleArchivedAction) {
		t.Errorf("archived should not fire when repo is unreadable: %+v", got)
	}
}

func TestAudit_StaleActionRef(t *testing.T) {
	pinned := "1111111111111111111111111111111111111111"
	tagged := "2222222222222222222222222222222222222222"
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: acme/action@` + pinned + `
`
	// The pinned SHA is not among the repo's tag SHAs → stale.
	got := auditYAML(t, yaml, &fakeAuditor{
		refs: map[string]string{"acme/action@" + pinned: pinned},
		tags: map[string][]string{"acme/action": {tagged}},
	})
	if !hasRule(got, RuleStaleActionRef) {
		t.Errorf("expected stale-action-ref finding, got %+v", got)
	}

	// Pinned SHA equals a tag SHA → clean.
	got = auditYAML(t, yaml, &fakeAuditor{
		refs: map[string]string{"acme/action@" + pinned: pinned},
		tags: map[string][]string{"acme/action": {pinned}},
	})
	if hasRule(got, RuleStaleActionRef) {
		t.Errorf("did not expect stale finding when pin matches a tag: %+v", got)
	}

	// No tags known → don't fire (avoid noise on repos we can't read tags for).
	got = auditYAML(t, yaml, &fakeAuditor{refs: map[string]string{"acme/action@" + pinned: pinned}})
	if hasRule(got, RuleStaleActionRef) {
		t.Errorf("stale should not fire with no tag data: %+v", got)
	}
}

func TestAudit_RefConfusion(t *testing.T) {
	yaml := `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: acme/action@release
`
	// "release" exists as both a branch and a tag → confusion.
	got := auditYAML(t, yaml, &fakeAuditor{
		branchRefs: map[string]bool{"acme/action@release": true},
		tagRefs:    map[string]bool{"acme/action@release": true},
	})
	if !hasRule(got, RuleRefConfusion) {
		t.Errorf("expected ref-confusion finding, got %+v", got)
	}

	// Only a tag → clean.
	got = auditYAML(t, yaml, &fakeAuditor{tagRefs: map[string]bool{"acme/action@release": true}})
	if hasRule(got, RuleRefConfusion) {
		t.Errorf("did not expect confusion when ref is only a tag: %+v", got)
	}
}
