package scanner

import (
	"strings"
	"testing"
)

// --- CICD-SEC-7: artifact exposure / missing retention ---------------------

func TestCheckArtifactExposure(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		want    int
		wantWhy string // substring of the description
	}{
		{
			name: "release workflow uploads an artifact with no retention cap",
			yaml: `
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
`,
			want:    1,
			wantWhy: "no retention-days",
		},
		{
			name: "secret-handling workflow uploads an artifact with no retention cap",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh
        env:
          TOKEN: ${{ secrets.BUILD_TOKEN }}
      - uses: actions/upload-artifact@v4
        with:
          name: out
          path: out/
`,
			want:    1,
			wantWhy: "no retention-days",
		},
		{
			name: "a credential-shaped path is sensitive on its own",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: config
          path: .env
`,
			want:    1,
			wantWhy: ".env",
		},
		{
			name: "retention longer than the cap is flagged",
			yaml: `
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
          retention-days: 365
`,
			want:    1,
			wantWhy: "365",
		},

		// --- must stay quiet ---------------------------------------------
		{
			name: "a short retention cap satisfies the rule",
			yaml: `
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
          retention-days: 7
`,
			want: 0,
		},
		{
			name: "exactly the cap satisfies the rule",
			yaml: `
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
          retention-days: 90
`,
			want: 0,
		},
		{
			name: "an ordinary build uploading an ordinary path is not sensitive",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
`,
			want: 0,
		},
		{
			name: "downloading an artifact is not publishing one",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh
        env:
          TOKEN: ${{ secrets.BUILD_TOKEN }}
      - uses: actions/download-artifact@v4
        with:
          name: dist
`,
			want: 0,
		},
		{
			name: "a templated retention value is not second-guessed",
			yaml: `
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
          retention-days: ${{ inputs.retention }}
`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanWF(t, tc.yaml, RuleArtifactExposure)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.want, got)
			}
			if tc.want == 0 {
				return
			}
			f := got[0]
			if f.Category != "CICD-SEC-7" {
				t.Errorf("got category %q, want CICD-SEC-7", f.Category)
			}
			if f.Severity != SeverityMedium {
				t.Errorf("got severity %q, want MEDIUM", f.Severity)
			}
			if !strings.Contains(f.Description, tc.wantWhy) {
				t.Errorf("description should mention %q: %s", tc.wantWhy, f.Description)
			}
			if f.Line == 0 {
				t.Error("finding has no line")
			}
		})
	}
}

// --- auto-fix ---------------------------------------------------------------

func TestFixArtifactExposureAddsRetention(t *testing.T) {
	const in = `on: push
jobs:
  release:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: npm publish
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
`
	got := scanWF(t, in, RuleArtifactExposure)
	if len(got) != 1 {
		t.Fatalf("fixture produced %d findings, want 1", len(got))
	}
	out, n, err := FixBytes([]byte(in), got)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if n != 1 {
		t.Fatalf("applied %d fixes, want 1", n)
	}
	s := string(out)
	if !strings.Contains(s, "retention-days: 90") {
		t.Errorf("fix did not add a retention cap:\n%s", s)
	}
	// Comment-guarded: 90 is a ceiling, not a recommendation, and the author
	// has to decide the real number for their artifact.
	if !strings.Contains(s, artifactRetentionFixMarker) {
		t.Errorf("fix should be comment-guarded:\n%s", s)
	}
	// The existing inputs must survive.
	if !strings.Contains(s, "name: dist") || !strings.Contains(s, "path: dist/") {
		t.Errorf("fix dropped existing with: inputs:\n%s", s)
	}
	// Clean on re-scan, and idempotent.
	after := scanWF(t, s, RuleArtifactExposure)
	if len(after) != 0 {
		t.Errorf("rule still fires after the fix: %+v\n%s", after, s)
	}
	if _, n2, err := FixBytes([]byte(s), got); err != nil || n2 != 0 {
		t.Errorf("second pass applied %d fixes (err=%v), want 0", n2, err)
	}
}

// A step with no with: block at all still gets one.
func TestFixArtifactExposureCreatesWithBlock(t *testing.T) {
	const in = `on: push
jobs:
  release:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: npm publish
      - uses: actions/upload-artifact@v4
`
	got := scanWF(t, in, RuleArtifactExposure)
	if len(got) != 1 {
		t.Fatalf("fixture produced %d findings, want 1", len(got))
	}
	out, n, err := FixBytes([]byte(in), got)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if n != 1 {
		t.Fatalf("applied %d fixes, want 1", n)
	}
	if !strings.Contains(string(out), "retention-days: 90") {
		t.Errorf("fix did not add a retention cap:\n%s", out)
	}
	if _, err := ScanBytes(".github/workflows/test.yml", out); err != nil {
		t.Fatalf("fixed output no longer parses: %v\n%s", err, out)
	}
}

// The debug-logging fixer shares CICD-SEC-7 and deletes the entry it is
// pointed at. Dispatch must not let it near an upload-artifact step.
func TestCICDSec7FixersDoNotCollide(t *testing.T) {
	const in = `on: push
env:
  ACTIONS_STEP_DEBUG: true
jobs:
  release:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: npm publish
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
`
	all, err := ScanBytes(".github/workflows/test.yml", []byte(in))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	var sec7 []Finding
	for _, f := range all {
		if f.Category == "CICD-SEC-7" {
			sec7 = append(sec7, f)
		}
	}
	if len(sec7) != 2 {
		t.Fatalf("expected both CICD-SEC-7 rules to fire, got %d: %+v", len(sec7), sec7)
	}
	out, _, err := FixBytes([]byte(in), sec7)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "ACTIONS_STEP_DEBUG") {
		t.Errorf("debug-logging entry was not removed:\n%s", s)
	}
	if !strings.Contains(s, "retention-days: 90") {
		t.Errorf("retention cap was not added:\n%s", s)
	}
	if !strings.Contains(s, "name: dist") || !strings.Contains(s, "path: dist/") {
		t.Errorf("the debug fixer ate the upload-artifact inputs:\n%s", s)
	}
}
