package scanner

import (
	"strings"
	"testing"
)

// --- CICD-SEC-8: self-hosted runner without declared egress control ---------

// These go through ScanBytes rather than the check directly: the
// acknowledgment surface is a YAML comment, and comments only survive a real
// parse. scanWF (parity_rules_test.go) already does exactly that.

func TestCheckSelfHostedEgress(t *testing.T) {
	cases := []struct {
		name     string
		yaml     string
		want     int
		wantWhy  string // substring of the description naming the sensitive trait
		wantConf Confidence
	}{
		{
			name: "self-hosted job consuming a secret",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`,
			want:     1,
			wantWhy:  "secret",
			wantConf: ConfidenceMedium,
		},
		{
			name: "self-hosted job in a label list consuming a secret",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: [self-hosted, linux, x64]
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`,
			want:     1,
			wantWhy:  "secret",
			wantConf: ConfidenceMedium,
		},
		{
			name: "self-hosted job under pull_request_target",
			yaml: `
on: pull_request_target
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: make build
`,
			want:     1,
			wantWhy:  "pull_request_target",
			wantConf: ConfidenceMedium,
		},
		{
			name: "self-hosted job publishing a release",
			yaml: `
on: push
jobs:
  release:
    runs-on: self-hosted
    steps:
      - uses: softprops/action-gh-release@v2
`,
			want:     1,
			wantWhy:  "publish",
			wantConf: ConfidenceMedium,
		},
		{
			name: "self-hosted job publishing via a run command",
			yaml: `
on: push
jobs:
  release:
    runs-on: self-hosted
    steps:
      - run: npm publish --access public
`,
			want:     1,
			wantWhy:  "publish",
			wantConf: ConfidenceMedium,
		},

		// --- must stay quiet ---------------------------------------------
		{
			name: "a self-hosted job doing nothing sensitive",
			yaml: `
on: push
jobs:
  lint:
    runs-on: self-hosted
    steps:
      - run: make lint
`,
			want: 0,
		},
		{
			name: "a GitHub-hosted job consuming a secret",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`,
			want: 0,
		},
		{
			name: "harden-runner with egress-policy block satisfies the rule",
			yaml: `
on: push
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: block
          allowed-endpoints: >
            api.github.com:443
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`,
			want: 0,
		},
		{
			name: "an explicit egress-restricted acknowledgment on the job",
			yaml: `
on: push
jobs:
  # pipefort: egress-restricted
  deploy:
    runs-on: self-hosted
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`,
			want: 0,
		},
		{
			name: "a workflow-level egress-restricted acknowledgment covers every job",
			yaml: `# pipefort: egress-restricted
on: push
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  publish:
    runs-on: self-hosted
    steps:
      - run: npm publish
`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanWF(t, tc.yaml, RuleSelfHostedEgress)
			if len(got) != tc.want {
				t.Fatalf("got %d findings, want %d (findings=%+v)", len(got), tc.want, got)
			}
			if tc.want == 0 {
				return
			}
			f := got[0]
			if f.Category != "CICD-SEC-8" {
				t.Errorf("got category %q, want CICD-SEC-8", f.Category)
			}
			if f.Severity != SeverityMedium {
				t.Errorf("got severity %q, want MEDIUM", f.Severity)
			}
			if f.Confidence != tc.wantConf {
				t.Errorf("got confidence %q, want %q", f.Confidence, tc.wantConf)
			}
			if !strings.Contains(strings.ToLower(f.Description), tc.wantWhy) {
				t.Errorf("description should name why the job is sensitive (%q): %s", tc.wantWhy, f.Description)
			}
			if !strings.Contains(f.Recommendation, "egress-restricted") {
				t.Errorf("recommendation should name the acknowledgment surface: %s", f.Recommendation)
			}
		})
	}
}

// harden-runner in audit mode observes egress; it does not restrict it. The
// finding must say so rather than staying silent or pretending it is absent.
func TestSelfHostedEgressNamesAuditModeExplicitly(t *testing.T) {
	const y = `
on: push
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: audit
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`
	got := scanWF(t, y, RuleSelfHostedEgress)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Description, "audit") {
		t.Errorf("description should name the audit-mode policy it found: %s", got[0].Description)
	}
}

// Advisory: egress control lives in runner infrastructure, not in the workflow
// file, so there is nothing for the fixer to write.
func TestSelfHostedEgressHasNoAutoFix(t *testing.T) {
	const y = `on: push
jobs:
  deploy:
    runs-on: self-hosted
    timeout-minutes: 10
    steps:
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`
	got := scanWF(t, y, RuleSelfHostedEgress)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	out, n, err := FixBytes([]byte(y), got)
	if err != nil {
		t.Fatalf("FixBytes: %v", err)
	}
	if out != nil || n != 0 {
		t.Errorf("fixer rewrote the file (%d fixes); this rule is advisory:\n%s", n, out)
	}
}

// --- GitLab CI --------------------------------------------------------------

func TestGitLabSelfHostedEgress(t *testing.T) {
	t.Run("a tagged runner job reading a masked variable", func(t *testing.T) {
		f := wantRule(t, scanGL(t, `
deploy:
  tags:
    - internal-runner
  script:
    - ./deploy.sh "$DEPLOY_TOKEN"
  variables:
    DEPLOY_TOKEN: $CI_DEPLOY_TOKEN
`), RuleSelfHostedEgress)
		if f.Category != "CICD-SEC-8" {
			t.Errorf("got category %q, want CICD-SEC-8", f.Category)
		}
	})

	t.Run("a SaaS-runner job is not self-hosted", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
deploy:
  tags:
    - saas-linux-medium-amd64
  script:
    - ./deploy.sh "$CI_DEPLOY_TOKEN"
`), RuleSelfHostedEgress)
	})

	t.Run("a tagged runner job doing nothing sensitive", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
lint:
  tags:
    - internal-runner
  script:
    - make lint
`), RuleSelfHostedEgress)
	})

	t.Run("an egress-restricted acknowledgment silences the job", func(t *testing.T) {
		wantNoRule(t, scanGL(t, `
# pipefort: egress-restricted
deploy:
  tags:
    - internal-runner
  script:
    - ./deploy.sh "$CI_DEPLOY_TOKEN"
`), RuleSelfHostedEgress)
	})
}
