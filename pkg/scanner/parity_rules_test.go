package scanner

import (
	"strings"
	"testing"
)

// scanWF parses a workflow and returns findings for the named rule only.
func scanWF(t *testing.T, yamlSrc string, rule RuleID) []Finding {
	t.Helper()
	all, err := ScanBytes(".github/workflows/test.yml", []byte(yamlSrc))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	var out []Finding
	for _, f := range all {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestCheckUnsoundCondition(t *testing.T) {
	cases := []struct {
		name string
		wf   string
		want int
	}{
		{
			name: "two expression blocks joined by literal text",
			wf: `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    if: ${{ github.event_name == 'push' }} && ${{ github.actor == 'x' }}
    steps: [{ run: echo hi }]`,
			want: 1,
		},
		{
			name: "literal text after an expression block",
			wf: `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - if: ${{ github.actor == 'x' }} always
        run: echo hi`,
			want: 1,
		},
		{
			name: "single well-formed expression block is fine",
			wf: `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    if: ${{ github.event_name == 'push' && github.actor == 'x' }}
    steps: [{ run: echo hi }]`,
			want: 0,
		},
		{
			name: "bare expression (no braces) is fine",
			wf: `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps: [{ run: echo hi }]`,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanWF(t, tc.wf, RuleUnsoundCondition); len(got) != tc.want {
				t.Errorf("got %d findings, want %d", len(got), tc.want)
			}
		})
	}
}

func TestCheckUnsoundContains(t *testing.T) {
	vuln := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    if: contains('refs/heads/main refs/heads/release', github.ref)
    steps: [{ run: echo hi }]`
	if got := scanWF(t, vuln, RuleUnsoundContains); len(got) != 1 {
		t.Fatalf("expected 1 finding on literal-haystack contains, got %d", len(got))
	}

	safe := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    if: contains(fromJSON('["main","release"]'), github.ref_name)
    steps: [{ run: echo hi }]`
	if got := scanWF(t, safe, RuleUnsoundContains); len(got) != 0 {
		t.Errorf("array-membership contains should be safe, got %d findings", len(got))
	}
}

func TestCheckObfuscatedExpression(t *testing.T) {
	idx := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github['event']['issue']['title'] }}"`
	if got := scanWF(t, idx, RuleObfuscatedExpr); len(got) != 1 {
		t.Fatalf("expected 1 index-notation finding, got %d", len(got))
	}

	b64 := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo aGVsbG8= | base64 -d | bash`
	if got := scanWF(t, b64, RuleObfuscatedExpr); len(got) != 1 {
		t.Fatalf("expected 1 decode-and-execute finding, got %d", len(got))
	}

	safe := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }}"`
	if got := scanWF(t, safe, RuleObfuscatedExpr); len(got) != 0 {
		t.Errorf("dotted access should be clean, got %d findings", len(got))
	}
}

func TestCheckCachePoisoningRelease(t *testing.T) {
	vuln := `on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache
          key: build-${{ hashFiles('**/lock') }}
      - run: gh release create v1`
	if got := scanWF(t, vuln, RuleCachePoisonRelease); len(got) != 1 {
		t.Fatalf("expected 1 cache-in-release finding, got %d", len(got))
	}

	// Caching in a non-publishing workflow is fine.
	safe := `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with: { path: ~/.cache, key: k }
      - run: make build`
	if got := scanWF(t, safe, RuleCachePoisonRelease); len(got) != 0 {
		t.Errorf("cache without publishing should be clean, got %d findings", len(got))
	}
}

func TestCheckOverprovisionedSecrets(t *testing.T) {
	tojson := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(secrets) }}' > /tmp/all`
	got := scanWF(t, tojson, RuleOverprovSecrets)
	if len(got) != 1 || got[0].Severity != SeverityHigh {
		t.Fatalf("expected 1 HIGH toJSON(secrets) finding, got %+v", got)
	}

	wfEnv := `on: push
env:
  TOKEN: ${{ secrets.DEPLOY_TOKEN }}
jobs:
  a:
    runs-on: ubuntu-latest
    steps: [{ run: echo hi }]`
	got = scanWF(t, wfEnv, RuleOverprovSecrets)
	if len(got) != 1 || got[0].Severity != SeverityMedium {
		t.Fatalf("expected 1 MEDIUM workflow-env finding, got %+v", got)
	}

	safe := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: deploy
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}`
	if got := scanWF(t, safe, RuleOverprovSecrets); len(got) != 0 {
		t.Errorf("step-scoped secret should be clean, got %d findings", len(got))
	}
}

func TestCheckUseTrustedPublishing(t *testing.T) {
	pypi := `on:
  release: { types: [published] }
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_TOKEN }}`
	if got := scanWF(t, pypi, RuleUseTrustedPublish); len(got) != 1 {
		t.Fatalf("expected 1 PyPI-token finding, got %d", len(got))
	}

	// OIDC trusted publishing (no password) is the good path.
	oidc := `on:
  release: { types: [published] }
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions: { id-token: write }
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1`
	if got := scanWF(t, oidc, RuleUseTrustedPublish); len(got) != 0 {
		t.Errorf("OIDC publish should be clean, got %d findings", len(got))
	}
}

func TestCheckMissingConcurrency(t *testing.T) {
	vuln := `on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1`
	if got := scanWF(t, vuln, RuleMissingConcurrency); len(got) != 1 {
		t.Fatalf("expected 1 missing-concurrency finding, got %d", len(got))
	}

	guarded := `on:
  push:
    tags: ['v*']
concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: true
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1`
	if got := scanWF(t, guarded, RuleMissingConcurrency); len(got) != 0 {
		t.Errorf("workflow with a concurrency guard should be clean, got %d findings", len(got))
	}

	// A plain build workflow (no publish/deploy) isn't required to guard.
	build := `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{ run: make }]`
	if got := scanWF(t, build, RuleMissingConcurrency); len(got) != 0 {
		t.Errorf("non-deploy workflow should not require concurrency, got %d findings", len(got))
	}
}

func TestPipeToShellExtendedForms(t *testing.T) {
	cases := map[string]string{
		"classic pipe":   `run: curl https://x.sh | bash`,
		"process sub":    `run: bash <(curl -s https://x.sh)`,
		"sh -c command":  `run: sh -c "$(curl -fsSL https://x.sh)"`,
		"powershell iex": `run: iex(iwr https://x.ps1)`,
	}
	for name, step := range cases {
		t.Run(name, func(t *testing.T) {
			wf := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - " + step
			got := scanWF(t, wf, RulePipeToShell)
			if len(got) == 0 {
				t.Errorf("expected pipe-to-shell finding for %q", strings.TrimPrefix(step, "run: "))
			}
		})
	}
}
