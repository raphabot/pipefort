package scanner

import (
	"strings"
	"testing"
)

// --- BEST-PRAC-5: strict-mode shell hardening -------------------------------

func TestCheckShellHardening(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{
			name: "multi-line default-shell run block is unhardened",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          make deps
          make build
`,
			want: 1,
		},
		{
			name: "multi-line explicit bash run block is unhardened",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - shell: bash
        run: |
          make deps
          make build
`,
			want: 1,
		},
		{
			name: "set -euo pipefail at the top hardens the block",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          set -euo pipefail
          make deps
          make build
`,
			want: 0,
		},
		{
			name: "set -o pipefail alone is enough",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          set -o pipefail
          make deps
          make build
`,
			want: 0,
		},
		{
			name: "a custom shell string carrying pipefail hardens the block",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - shell: bash -euo pipefail {0}
        run: |
          make deps
          make build
`,
			want: 0,
		},
		{
			name: "a shebang with pipefail hardens the block",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          #!/usr/bin/env bash
          set -euo pipefail
          make build
          make test
`,
			want: 0,
		},
		{
			name: "single-line run blocks are out of scope",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`,
			want: 0,
		},
		{
			name: "non-bash shells are out of scope",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - shell: pwsh
        run: |
          Get-ChildItem
          Write-Host done
      - shell: python
        run: |
          import os
          print(os.getcwd())
      - shell: sh
        run: |
          make deps
          make build
`,
			want: 0,
		},
		{
			name: "windows runners default to pwsh, not bash",
			yaml: `
on: push
jobs:
  build:
    runs-on: windows-latest
    steps:
      - run: |
          Get-ChildItem
          Write-Host done
`,
			want: 0,
		},
		{
			name: "an explicit bash shell on windows is still bash",
			yaml: `
on: push
jobs:
  build:
    runs-on: windows-latest
    steps:
      - shell: bash
        run: |
          make deps
          make build
`,
			want: 1,
		},
		{
			name: "uses: steps have no run block",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			want: 0,
		},
		{
			name: "blank lines and comments do not make a block multi-line",
			yaml: `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |

          # build it
          make build
`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, jobs := parseTestWorkflow(t, tc.yaml)
			got := CheckShellHardening("test.yml", wf, jobs)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.want, got)
			}
			if tc.want == 0 {
				return
			}
			f := got[0]
			if f.RuleID != RuleShellHardening {
				t.Errorf("got rule %q, want %q", f.RuleID, RuleShellHardening)
			}
			if f.Category != "BEST-PRAC-5" {
				t.Errorf("got category %q, want BEST-PRAC-5", f.Category)
			}
			if f.Severity != SeverityLow {
				t.Errorf("got severity %q, want LOW", f.Severity)
			}
			if !strings.Contains(f.Recommendation, "set -euo pipefail") {
				t.Errorf("recommendation should name the fix: %s", f.Recommendation)
			}
			if f.Line == 0 {
				t.Error("finding has no line")
			}
		})
	}
}

// The rule is tiered to the pedantic persona: it is real, but it fires on
// ordinary CI and must not crowd out security findings at the default tier.
func TestShellHardeningIsPedantic(t *testing.T) {
	spec, ok := RuleByID()[RuleShellHardening]
	if !ok {
		t.Fatalf("%s missing from the catalog", RuleShellHardening)
	}
	if spec.Persona != PersonaPedantic {
		t.Errorf("got persona %q, want %q", spec.Persona, PersonaPedantic)
	}

	findings := []Finding{{RuleID: RuleShellHardening, Title: "shell"}}
	if got := FilterByPersona(findings, PersonaRegular); len(got) != 0 {
		t.Errorf("regular persona should drop the finding, got %d", len(got))
	}
	if got := FilterByPersona(findings, PersonaPedantic); len(got) != 1 {
		t.Errorf("pedantic persona should keep the finding, got %d", len(got))
	}
}

// --- auto-fix ---------------------------------------------------------------

func TestFixShellHardeningPrependsStrictMode(t *testing.T) {
	const in = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: |
          make deps
          make build
`
	findings, err := ScanBytes(".github/workflows/ci.yml", []byte(in))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	var sh []Finding
	for _, f := range findings {
		if f.RuleID == RuleShellHardening {
			sh = append(sh, f)
		}
	}
	if len(sh) != 1 {
		t.Fatalf("fixture produced %d findings, want 1", len(sh))
	}

	out, n, err := FixBytes([]byte(in), sh)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if n != 1 {
		t.Fatalf("applied %d fixes, want 1", n)
	}
	got := string(out)
	if !strings.Contains(got, "set -euo pipefail") {
		t.Fatalf("fix did not add strict mode:\n%s", got)
	}
	// Strict mode must come FIRST — after it, the original commands, in order.
	i := strings.Index(got, "set -euo pipefail")
	if d := strings.Index(got, "make deps"); d < i {
		t.Errorf("strict mode must precede the script body:\n%s", got)
	}
	if !strings.Contains(got, "make deps") || !strings.Contains(got, "make build") {
		t.Errorf("fix dropped script lines:\n%s", got)
	}

	// The fixed file must be clean on a re-scan, and the fix idempotent.
	after, err := ScanBytes(".github/workflows/ci.yml", []byte(got))
	if err != nil {
		t.Fatalf("fixed output no longer parses: %v\n%s", err, got)
	}
	for _, f := range after {
		if f.RuleID == RuleShellHardening {
			t.Errorf("rule still fires after the fix:\n%s", got)
		}
	}
}

func TestFixShellHardeningKeepsShebangFirst(t *testing.T) {
	const in = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: |
          #!/usr/bin/env bash
          make deps
          make build
`
	findings, err := ScanBytes(".github/workflows/ci.yml", []byte(in))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	var sh []Finding
	for _, f := range findings {
		if f.RuleID == RuleShellHardening {
			sh = append(sh, f)
		}
	}
	if len(sh) != 1 {
		t.Fatalf("fixture produced %d findings, want 1", len(sh))
	}
	out, _, err := FixBytes([]byte(in), sh)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	got := string(out)
	shebang := strings.Index(got, "#!/usr/bin/env bash")
	strict := strings.Index(got, "set -euo pipefail")
	if shebang == -1 || strict == -1 {
		t.Fatalf("expected both the shebang and strict mode:\n%s", got)
	}
	if shebang > strict {
		t.Errorf("a shebang must stay on the first line:\n%s", got)
	}
}

// --- GitLab CI --------------------------------------------------------------

func TestGitLabShellHardening(t *testing.T) {
	t.Run("a multi-command script is unhardened", func(t *testing.T) {
		f := wantRule(t, scanGL(t, `
build:
  script:
    - make deps
    - make build
`), RuleShellHardening)
		if f.Category != "BEST-PRAC-5" {
			t.Errorf("got category %q, want BEST-PRAC-5", f.Category)
		}
		if !strings.Contains(f.Description, "build") {
			t.Errorf("description should name the job: %s", f.Description)
		}
	})

	t.Run("set -o pipefail in before_script hardens the job", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
build:
  before_script:
    - set -euo pipefail
  script:
    - make deps
    - make build
`), RuleShellHardening)
	})

	t.Run("set -euo pipefail in the script hardens the job", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
build:
  script:
    - set -euo pipefail
    - make deps
    - make build
`), RuleShellHardening)
	})

	t.Run("a single-command script is out of scope", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
build:
  script:
    - make build
`), RuleShellHardening)
	})

	t.Run("a top-level default before_script hardens every job", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
default:
  before_script:
    - set -euo pipefail

build:
  script:
    - make deps
    - make build
`), RuleShellHardening)
	})
}
