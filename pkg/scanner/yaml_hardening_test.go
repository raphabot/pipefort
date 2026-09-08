package scanner

import (
	"strings"
	"testing"
)

// --- CICD-SEC-1: unsafe YAML tags and parser-bomb hazards -------------------

func TestCheckYAMLHardeningUnsafeTags(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
		tag  string
	}{
		{
			name: "python object tag",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: !!python/object/apply:os.system ["id"]
`,
			want: 1,
			tag:  "!!python/object/apply:os.system",
		},
		{
			name: "ruby object tag",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: !ruby/object:Gem::Requirement {}
`,
			want: 1,
			tag:  "!ruby/object:Gem::Requirement",
		},
		{
			name: "php object tag",
			yaml: `
on: push
env:
  X: !!php/object "O:8:\"stdClass\":0:{}"
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			want: 1,
			tag:  "!!php/object",
		},
		{
			name: "core-schema tags are safe",
			yaml: `
on: push
env:
  A: !!str hello
  B: !!int 3
  C: !!bool true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			want: 0,
		},
		{
			name: "an ordinary workflow has no explicit tags at all",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterRule(CheckYAMLHardening("test.yml", []byte(tc.yaml)), RuleYAMLHardening)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.want, got)
			}
			if tc.want == 0 {
				return
			}
			f := got[0]
			if f.Category != "CICD-SEC-1" {
				t.Errorf("got category %q, want CICD-SEC-1", f.Category)
			}
			if f.Severity != SeverityHigh {
				t.Errorf("got severity %q, want HIGH (unsafe tags block)", f.Severity)
			}
			if f.Confidence != ConfidenceHigh {
				t.Errorf("got confidence %q, want HIGH", f.Confidence)
			}
			if !strings.Contains(f.Description, tc.tag) {
				t.Errorf("description should name the tag %q: %s", tc.tag, f.Description)
			}
			if f.Line == 0 {
				t.Error("finding has no line")
			}
		})
	}
}

// GitLab's !reference is a first-class part of the .gitlab-ci.yml language.
// Flagging it would make the rule unusable on the platform it ships for.
func TestYAMLHardeningAllowsGitLabReference(t *testing.T) {
	const y = `
.tmpl:
  script:
    - make build

build:
  script:
    - !reference [.tmpl, script]
`
	if got := filterRule(CheckYAMLHardening(".gitlab-ci.yml", []byte(y)), RuleYAMLHardening); len(got) != 0 {
		t.Fatalf("!reference must not be flagged, got %+v", got)
	}
	// And it must stay quiet through the real entry point too.
	if got := scanGLRule(t, y, RuleYAMLHardening); len(got) != 0 {
		t.Fatalf("!reference flagged via ScanBytes: %+v", got)
	}
}

func TestCheckYAMLHardeningParserBomb(t *testing.T) {
	// The billion-laughs shape: each anchor is a list of aliases to the
	// previous anchor, so the expanded size multiplies at every level.
	const bomb = `
on: push
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	got := filterRule(CheckYAMLHardening("test.yml", []byte(bomb)), RuleYAMLHardening)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != SeverityMedium {
		t.Errorf("got severity %q, want MEDIUM (expansion warns, it does not block)", f.Severity)
	}
	if f.Confidence != ConfidenceMedium {
		t.Errorf("got confidence %q, want MEDIUM", f.Confidence)
	}
	if !strings.Contains(f.Description, "expand") {
		t.Errorf("description should explain the expansion: %s", f.Description)
	}
}

// Flat anchor reuse is the ordinary, correct way to share configuration and
// must never fire — however many times the anchor is used. Nesting is what
// makes a bomb, so nesting is what the rule keys on.
func TestYAMLHardeningAllowsFlatAnchorReuse(t *testing.T) {
	var b strings.Builder
	b.WriteString(".defaults: &defaults\n  image: alpine:3\n  before_script:\n    - make deps\n\n")
	for i := 0; i < 60; i++ {
		b.WriteString("job")
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + i/26)))
		b.WriteString(":\n  <<: *defaults\n  script:\n    - make build\n\n")
	}
	if got := filterRule(CheckYAMLHardening(".gitlab-ci.yml", []byte(b.String())), RuleYAMLHardening); len(got) != 0 {
		t.Fatalf("flat anchor reuse must not fire, got %+v", got)
	}
}

// Two levels of template inheritance with small bodies is a real pattern in
// large .gitlab-ci.yml files. It nests, but it does not multiply.
func TestYAMLHardeningAllowsShallowNestedTemplates(t *testing.T) {
	const y = `
.base: &base
  image: alpine:3

.withdeps: &withdeps
  <<: *base
  before_script:
    - make deps

build:
  <<: *withdeps
  script:
    - make build

test:
  <<: *withdeps
  script:
    - make test
`
	if got := filterRule(CheckYAMLHardening(".gitlab-ci.yml", []byte(y)), RuleYAMLHardening); len(got) != 0 {
		t.Fatalf("shallow nested templates must not fire, got %+v", got)
	}
}

// The rule must reach findings through the normal entry point on both
// platforms, and must not offer an auto-fix.
func TestYAMLHardeningWiredIntoScanBytes(t *testing.T) {
	const gh = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: !!python/object/apply:os.system ["id"]
`
	got := scanWF(t, gh, RuleYAMLHardening)
	if len(got) != 1 {
		t.Fatalf("GitHub Actions: got %d findings, want 1: %+v", len(got), got)
	}

	const gl = `build:
  script:
    - !!python/object/apply:os.system ["id"]
`
	if n := len(scanGLRule(t, gl, RuleYAMLHardening)); n != 1 {
		t.Fatalf("GitLab CI: got %d findings, want 1", n)
	}

	out, n, err := FixBytes([]byte(gh), got)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if out != nil || n != 0 {
		t.Errorf("fixer rewrote the file (%d fixes); this rule is flag-only:\n%s", n, out)
	}
}

// filterRule keeps only the findings for one rule.
func filterRule(findings []Finding, rule RuleID) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

// scanGLRule is scanWF's GitLab sibling.
func scanGLRule(t *testing.T, src string, rule RuleID) []Finding {
	t.Helper()
	return filterRule(scanGL(t, src), rule)
}
