package scanner

import "testing"

const reusableWorkflowYAML = `name: ci
on: push
jobs:
  call:
    uses: octo/repo/.github/workflows/ci.yml@v1
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`

func TestCollectReusableWorkflowRefs_Basic(t *testing.T) {
	refs := CollectReusableWorkflowRefsFromBytes(".github/workflows/ci.yml", []byte(reusableWorkflowYAML))
	if len(refs) != 1 {
		t.Fatalf("expected 1 reusable-workflow ref, got %d: %+v", len(refs), refs)
	}
	r := refs[0]
	if r.Kind != RefKindReusableWorkflow {
		t.Errorf("Kind = %q, want %q", r.Kind, RefKindReusableWorkflow)
	}
	if r.Owner != "octo" || r.Repo != "repo" {
		t.Errorf("owner/repo = %s/%s, want octo/repo", r.Owner, r.Repo)
	}
	if r.Path != ".github/workflows/ci.yml" {
		t.Errorf("Path = %q, want .github/workflows/ci.yml", r.Path)
	}
	if r.Ref != "v1" {
		t.Errorf("Ref = %q, want v1", r.Ref)
	}
}

// The step-level collector must NOT pick up job-level reusable calls (and must
// tag what it does collect as an action) — the two surfaces stay separate so
// detection/pin-audit behavior is unchanged.
func TestCollectActionRefs_IgnoresJobLevelUsesAndTagsKind(t *testing.T) {
	refs := CollectActionRefsFromBytes(".github/workflows/ci.yml", []byte(reusableWorkflowYAML))
	if len(refs) != 1 {
		t.Fatalf("expected 1 action ref (checkout only), got %d: %+v", len(refs), refs)
	}
	if refs[0].Owner != "actions" || refs[0].Repo != "checkout" {
		t.Fatalf("expected actions/checkout, got %s/%s", refs[0].Owner, refs[0].Repo)
	}
	if refs[0].Kind != RefKindAction {
		t.Errorf("action Kind = %q, want %q", refs[0].Kind, RefKindAction)
	}
	if refs[0].Path != "" {
		t.Errorf("action Path should be empty, got %q", refs[0].Path)
	}
}

func TestCollectReusableWorkflowRefs_SkipsLocalCalls(t *testing.T) {
	yaml := `name: ci
on: push
jobs:
  call-local:
    uses: ./.github/workflows/local.yml
`
	refs := CollectReusableWorkflowRefsFromBytes(".github/workflows/ci.yml", []byte(yaml))
	if len(refs) != 0 {
		t.Fatalf("local reusable calls must be skipped, got %+v", refs)
	}
}

func TestCollectReusableWorkflowRefs_GitLabYieldsNothing(t *testing.T) {
	if refs := CollectReusableWorkflowRefsFromBytes(".gitlab-ci.yml", []byte("stages: [build]\n")); refs != nil {
		t.Fatalf("GitLab files have no reusable-workflow surface, got %+v", refs)
	}
}
