package scanner

import (
	"strings"
	"testing"
)

// Each subtest names the rule it exercises plus a short description of the
// triggering shape; the comment block at the top of each fixture explains the
// MR-target / shell-injection / etc. that the YAML is meant to flag.

func scanGL(t *testing.T, yaml string) []Finding {
	t.Helper()
	out, err := ScanBytes(".gitlab-ci.yml", []byte(yaml))
	if err != nil {
		t.Fatalf("ScanBytes returned an error: %v", err)
	}
	return out
}

func wantRule(t *testing.T, findings []Finding, id RuleID) Finding {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == id {
			return f
		}
	}
	t.Fatalf("expected rule %s to fire; got %d findings (rule IDs: %s)", id, len(findings), ruleIDs(findings))
	return Finding{}
}

func wantNoRule(t *testing.T, findings []Finding, id RuleID) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == id {
			t.Fatalf("rule %s fired unexpectedly: %+v", id, f)
		}
	}
}

func ruleIDs(findings []Finding) string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, string(f.RuleID))
	}
	return strings.Join(ids, ", ")
}

// --- isGitLabCIPath dispatch ----------------------------------------------

func TestIsGitLabCIPath(t *testing.T) {
	cases := map[string]bool{
		".gitlab-ci.yml":            true,
		".gitlab-ci.yaml":           true,
		".gitlab-ci/test.yml":       true,
		".gitlab-ci/sub/deploy.yml": true,
		".gitlab-ci/notes.md":       false,
		".github/workflows/ci.yml":  false,
		"random/.gitlab-ci/ci.yml":  true, // nested template dir
		"src/code.go":               false,
	}
	for p, want := range cases {
		if got := IsGitLabCIPath(p); got != want {
			t.Errorf("IsGitLabCIPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// --- Rule firings ----------------------------------------------------------

func TestGitLabMRTargetFires(t *testing.T) {
	const y = `
stages: [test]
poisoned:
  stage: test
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - git fetch origin "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
    - bash ./scripts/run-tests.sh
`
	f := wantRule(t, scanGL(t, y), RuleGitLabMRTarget)
	if f.Severity != SeverityHigh {
		t.Errorf("MR target finding should be HIGH, got %s", f.Severity)
	}
}

func TestGitLabPATSecretFires(t *testing.T) {
	const y = `
variables:
  GITLAB_TOKEN: $GITLAB_TOKEN_SECRET
deploy:
  script:
    - curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://gitlab.com/api/v4/projects
`
	f := wantRule(t, scanGL(t, y), RuleGitLabPATSecret)
	if f.Severity != SeverityMedium {
		t.Errorf("PAT secret finding should be MEDIUM, got %s", f.Severity)
	}
}

func TestGitLabUnpinnedIncludeFiresOnProjectWithoutRef(t *testing.T) {
	const y = `
include:
  - project: 'group/ci-templates'
    file: '/templates/build.yml'

build:
  script: echo hi
`
	wantRule(t, scanGL(t, y), RuleGitLabUnpinnedInclude)
}

func TestGitLabUnpinnedIncludeFiresOnRemoteMapping(t *testing.T) {
	const y = `
include:
  - remote: 'https://example.com/pipeline.yml'

build:
  script: echo hi
`
	wantRule(t, scanGL(t, y), RuleGitLabUnpinnedInclude)
}

func TestGitLabUnpinnedIncludeIgnoresPinnedSHA(t *testing.T) {
	const y = `
include:
  - project: 'group/ci-templates'
    ref: 0123456789abcdef0123456789abcdef01234567
    file: '/templates/build.yml'

build:
  script: echo hi
`
	wantNoRule(t, scanGL(t, y), RuleGitLabUnpinnedInclude)
}

func TestGitLabShellInjectionFires(t *testing.T) {
	const y = `
mr_check:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - echo "MR title is $CI_MERGE_REQUEST_TITLE"
`
	wantRule(t, scanGL(t, y), RuleGitLabShellInjection)
}

func TestGitLabHardcodedSecretsFires(t *testing.T) {
	const y = `
variables:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
deploy:
  script: echo hi
`
	wantRule(t, scanGL(t, y), RuleGitLabHardcodedSecrets)
}

func TestGitLabDebugTraceFires(t *testing.T) {
	const y = `
variables:
  CI_DEBUG_TRACE: "true"
deploy:
  script: echo hi
`
	wantRule(t, scanGL(t, y), RuleGitLabDebugTrace)
}

func TestGitLabDebugTraceQuietWhenFalse(t *testing.T) {
	const y = `
variables:
  CI_DEBUG_TRACE: "false"
deploy:
  script: echo hi
`
	wantNoRule(t, scanGL(t, y), RuleGitLabDebugTrace)
}

func TestGitLabTriggerUnfilteredFires(t *testing.T) {
	const y = `
downstream:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "trigger"'
  script: echo "from upstream"
`
	wantRule(t, scanGL(t, y), RuleGitLabTriggerUnfiltered)
}

func TestGitLabTriggerScopedSkipped(t *testing.T) {
	const y = `
downstream:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "trigger" && $CI_PROJECT_PATH == "group/known"'
  script: echo "from upstream"
`
	wantNoRule(t, scanGL(t, y), RuleGitLabTriggerUnfiltered)
}

func TestGitLabAllowFailureFires(t *testing.T) {
	const y = `
flaky:
  allow_failure: true
  script: echo hi
`
	wantRule(t, scanGL(t, y), RuleGitLabAllowFailure)
}

func TestGitLabMissingTimeoutFires(t *testing.T) {
	const y = `
slow_job:
  script: sleep 60
`
	wantRule(t, scanGL(t, y), RuleGitLabMissingTimeout)
}

func TestGitLabMissingTimeoutSatisfiedByDefault(t *testing.T) {
	const y = `
default:
  timeout: 30m
slow_job:
  script: sleep 60
`
	wantNoRule(t, scanGL(t, y), RuleGitLabMissingTimeout)
}

func TestGitLabSelfHostedTagsFires(t *testing.T) {
	const y = `
build:
  tags: [self-hosted, linux]
  script: make build
`
	wantRule(t, scanGL(t, y), RuleGitLabSelfHostedTags)
}

func TestGitLabSelfHostedTagsIgnoresSaaSRunners(t *testing.T) {
	const y = `
build:
  tags: [saas-linux-medium-amd64]
  script: make build
`
	wantNoRule(t, scanGL(t, y), RuleGitLabSelfHostedTags)
}

// --- Portable rules fire on .gitlab-ci.yml --------------------------------

func TestGitLabPortablePipeToShellFires(t *testing.T) {
	const y = `
deploy:
  script:
    - curl -fsSL https://example.com/install | bash
`
	wantRule(t, scanGL(t, y), RulePipeToShell)
}

func TestGitLabPortableDownloadNoChecksumFires(t *testing.T) {
	const y = `
deploy:
  script:
    - curl -fsSL -o tool.tar.gz https://example.com/tool.tar.gz
    - tar -xzf tool.tar.gz
`
	wantRule(t, scanGL(t, y), RuleDownloadNoChecksum)
}

func TestGitLabPortableDownloadSilentWhenVerified(t *testing.T) {
	const y = `
deploy:
  script:
    - curl -fsSL -o tool.tar.gz https://example.com/tool.tar.gz
    - echo "abc123  tool.tar.gz" | sha256sum -c
    - tar -xzf tool.tar.gz
`
	wantNoRule(t, scanGL(t, y), RuleDownloadNoChecksum)
}

// --- Empty / unrelated content ---------------------------------------------

func TestGitLabEmptyContentReturnsNoFindings(t *testing.T) {
	out, err := ScanBytes(".gitlab-ci.yml", []byte("# just a comment\n"))
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no findings, got %d", len(out))
	}
}
