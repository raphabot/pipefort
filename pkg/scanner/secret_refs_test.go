package scanner

import "testing"

const refsWorkflow = `
name: deploy
on: [push]
env:
  GLOBAL_TOKEN: ${{ secrets.ORG_WIDE }}
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      NPM: ${{ secrets.NPM_PUBLISH_TOKEN }}
    steps:
      - name: publish
        run: npm publish --token "$NPM"
      - name: notify
        if: secrets.SLACK_WEBHOOK != ''
        run: curl -d x ${{ secrets.SLACK_WEBHOOK }}
      - name: never listed
        run: gh api /user --header "bearer ${{ secrets.GITHUB_TOKEN }}"
  call:
    uses: acme/central/.github/workflows/release.yml@main
    secrets: inherit
`

func refNames(refs []SecretRef, kind SecretRefKind) []string {
	out := []string{}
	for _, r := range refs {
		if r.Kind == kind {
			out = append(out, r.Name)
		}
	}
	return out
}

func TestSecretReferencesFindsEveryPlaceASecretIsRead(t *testing.T) {
	refs := SecretReferences(".github/workflows/deploy.yml", []byte(refsWorkflow))
	got := SecretNamesRead(refs)
	want := []string{"NPM_PUBLISH_TOKEN", "ORG_WIDE", "SLACK_WEBHOOK"}
	if len(got) != len(want) {
		t.Fatalf("named secrets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("named secrets = %v, want %v", got, want)
		}
	}
}

// A workflow-level env reference belongs to no job, and saying it belongs to
// the first one would put the reader in the wrong place in the file.
func TestSecretReferencesAttributesJobAndLine(t *testing.T) {
	refs := SecretReferences(".github/workflows/deploy.yml", []byte(refsWorkflow))
	byName := map[string]SecretRef{}
	for _, r := range refs {
		if r.Kind == SecretRefNamed {
			byName[r.Name] = r
		}
	}
	if got := byName["ORG_WIDE"].Job; got != "" {
		t.Errorf("ORG_WIDE job = %q, want empty (it is workflow-level)", got)
	}
	if got := byName["NPM_PUBLISH_TOKEN"].Job; got != "build" {
		t.Errorf("NPM_PUBLISH_TOKEN job = %q, want build", got)
	}
	if byName["NPM_PUBLISH_TOKEN"].Line == 0 {
		t.Error("a reference without a line cannot be linked to")
	}
	if got := byName["NPM_PUBLISH_TOKEN"].File; got != ".github/workflows/deploy.yml" {
		t.Errorf("file = %q", got)
	}
}

// The per-run token is minted, not stored. Listing it would put a row in the
// inventory that nobody can rotate.
func TestSecretReferencesExcludesGitHubToken(t *testing.T) {
	for _, name := range SecretNamesRead(SecretReferences("w.yml", []byte(refsWorkflow))) {
		if name == "GITHUB_TOKEN" || name == "github_token" {
			t.Fatalf("GITHUB_TOKEN should never be reported, got %v", name)
		}
	}
}

// `secrets: inherit` names nothing and hands over everything. A consumer that
// missed it would report "nothing reads DEPLOY_KEY" about a workflow that
// reads all of them.
func TestSecretReferencesReportsInherit(t *testing.T) {
	refs := SecretReferences(".github/workflows/deploy.yml", []byte(refsWorkflow))
	var inherit *SecretRef
	for i := range refs {
		if refs[i].Kind == SecretRefInherit {
			inherit = &refs[i]
		}
	}
	if inherit == nil {
		t.Fatal("secrets: inherit was not reported")
	}
	if inherit.Job != "call" {
		t.Errorf("inherit job = %q, want call", inherit.Job)
	}
	if inherit.Target != "acme/central/.github/workflows/release.yml@main" {
		t.Errorf("inherit target = %q — the reader needs to know where the secrets went", inherit.Target)
	}
	if !ReadsEverySecret(refs) {
		t.Error("ReadsEverySecret must be true when a job inherits")
	}
}

// "inherit" is an ordinary word. Only the job-level secrets: key means this.
func TestSecretReferencesIgnoresTheWordInheritElsewhere(t *testing.T) {
	wf := `
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: secrets inherit from the parent config
        run: echo "inherit"
`
	refs := SecretReferences("w.yml", []byte(wf))
	if ReadsEverySecret(refs) {
		t.Errorf("a step named after the word must not read as secrets: inherit — got %+v", refs)
	}
}

func TestSecretReferencesReportsWholeContextReads(t *testing.T) {
	wf := `
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(secrets) }}' > /tmp/all
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets[format('KEY_{0}', matrix.env)] }}"
`
	refs := SecretReferences("w.yml", []byte(wf))
	if got := len(refNames(refs, SecretRefAll)); got != 2 {
		t.Errorf("whole-context reads = %d, want 2 (toJSON and the index): %+v", got, refs)
	}
	if !ReadsEverySecret(refs) {
		t.Error("ReadsEverySecret must be true for a whole-context read")
	}
	// It names nothing, so it must not invent a name.
	for _, r := range refs {
		if r.Kind == SecretRefAll && r.Name != "" {
			t.Errorf("a whole-context read named %q — it identifies no single secret", r.Name)
		}
	}
}

// A name reached both as ${{ secrets.X }} and bare in an if: on the same line
// is one reference, not two.
func TestSecretReferencesDeduplicatesWithinALine(t *testing.T) {
	wf := `
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - if: ${{ secrets.TOKEN }} != '' && secrets.TOKEN
        run: echo ok
`
	refs := SecretReferences("w.yml", []byte(wf))
	if got := len(refNames(refs, SecretRefNamed)); got != 1 {
		t.Errorf("named refs = %d, want 1: %+v", got, refs)
	}
}

// Silence, not an error — a sweep should not end because one file is odd.
func TestSecretReferencesIgnoresNonWorkflows(t *testing.T) {
	if refs := SecretReferences("readme.md", []byte("# not yaml: [")); refs != nil {
		t.Errorf("unparseable file should yield nil, got %+v", refs)
	}
	if refs := SecretReferences("config.yml", []byte("foo: bar\n")); refs != nil {
		t.Errorf("a non-workflow YAML file should yield nil, got %+v", refs)
	}
}
