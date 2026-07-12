package scanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "workflow-fix-test-*.yml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return tmpFile.Name()
}

func TestFixPBAC(t *testing.T) {
	vulnerableYAML := `name: Test PBAC
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	// The fixture also lacks timeout-minutes, so the fixer legitimately applies
	// the BEST-PRAC-2 fix too; assert at least one fix (matches sibling tests).
	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	// Verify the fix is applied and vulnerability is gone
	newFindings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("re-scan failed: %v", err)
	}
	for _, f := range newFindings {
		if f.Category == "CICD-SEC-5" {
			t.Errorf("expected PBAC vulnerability to be fixed, but it was found in re-scan")
		}
	}

	// Verify content indeed contains permissions: read-all
	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if !strings.Contains(string(updatedContent), "permissions: read-all") {
		t.Errorf("updated content does not contain permissions block: %s", string(updatedContent))
	}
}

func TestFixPRTarget(t *testing.T) {
	vulnerableYAML := `name: Test PR Target
on:
  pull_request_target:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	// Should change pull_request_target to pull_request
	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	// Verify the trigger was updated
	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if strings.Contains(string(updatedContent), "pull_request_target") {
		t.Errorf("updated content still contains pull_request_target: %s", string(updatedContent))
	}
	if !strings.Contains(string(updatedContent), "pull_request:") {
		t.Errorf("updated content does not contain pull_request trigger: %s", string(updatedContent))
	}
}

func TestFixTimeout(t *testing.T) {
	vulnerableYAML := `name: Test Timeout
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	// Should apply timeout-minutes fix
	// (Will also fix PBAC, but let's see how many fixes are applied)
	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if !strings.Contains(string(updatedContent), "timeout-minutes: 30") {
		t.Errorf("updated content does not contain timeout-minutes: %s", string(updatedContent))
	}
}

func TestFixUnsoundCondition(t *testing.T) {
	vulnerableYAML := `name: Guard
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    if: ${{ github.event_name == 'push' }} && ${{ github.actor == 'x' }}
    steps:
      - run: echo hi
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if _, err := FixFile(filePath, findings); err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	updated, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	// The two blocks are merged into a single expression, so re-scanning finds
	// no unsound-condition finding.
	if strings.Contains(string(updated), "}} && ${{") {
		t.Errorf("condition not merged: %s", updated)
	}
	refindings, _ := ScanFile(filePath)
	for _, f := range refindings {
		if f.RuleID == RuleUnsoundCondition {
			t.Errorf("unsound condition still present after fix: %s", updated)
		}
	}
}

func TestFixMissingConcurrency(t *testing.T) {
	vulnerableYAML := `name: Release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if _, err := FixFile(filePath, findings); err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	updated, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "concurrency:") ||
		!strings.Contains(string(updated), "cancel-in-progress") {
		t.Errorf("concurrency block not inserted: %s", updated)
	}
}

func TestFixUnpinnedAction(t *testing.T) {
	// Set up local test server to mock GitHub API response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/commits/v4") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"sha": "b4ffde65f46336ab88eb53be808477a3936bae11"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// Override API base URL
	oldBaseURL := githubAPIBaseURL
	githubAPIBaseURL = ts.URL
	defer func() { githubAPIBaseURL = oldBaseURL }()

	vulnerableYAML := `name: Test Unpinned Action
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Should contain unpinned action finding
	hasUnpinned := false
	for _, f := range findings {
		if f.Category == "CICD-SEC-3" {
			hasUnpinned = true
		}
	}
	if !hasUnpinned {
		t.Fatalf("expected unpinned action finding, got: %v", findings)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	expectedString := "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"
	if !strings.Contains(string(updatedContent), expectedString) {
		t.Errorf("updated content does not contain pinned SHA action: %s", string(updatedContent))
	}
	// Verify tag comment is present
	if !strings.Contains(string(updatedContent), "# v4") {
		t.Errorf("updated content does not contain original tag comment: %s", string(updatedContent))
	}
}

func TestFixHardcodedSecret(t *testing.T) {
	vulnerableYAML := `name: Test Hardcoded Secret
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        env:
          SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        run: echo "deploying"
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	expectedString := "SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}"
	if !strings.Contains(string(updatedContent), expectedString) {
		t.Errorf("updated content does not replace literal secret with secrets block: %s", string(updatedContent))
	}
}

func TestFixHardcodedSecretInRun(t *testing.T) {
	// Vulnerable: inline run script embeds a GitHub PAT and an AWS access key.
	// The fixer should hoist both into the step's env block and replace the
	// literals with $GH_TOKEN / $AWS_ACCESS_KEY_ID references.
	vulnerableYAML := `name: Test inline-script secret
on: push
permissions: read-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Push and configure
        run: |
          curl -H "Authorization: token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" https://api.github.com/user
          aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if _, err := FixFile(filePath, findings); err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	newFindings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("re-scan failed: %v", err)
	}
	for _, f := range newFindings {
		if f.Category == "CICD-SEC-6" {
			t.Errorf("expected CICD-SEC-6 to be fixed, still found: %s — %s", f.Title, f.Description)
		}
	}

	updated, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	got := string(updated)

	// Literals are gone.
	if strings.Contains(got, "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Errorf("PAT literal still present: %s", got)
	}
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key literal still present: %s", got)
	}
	// References swapped in.
	if !strings.Contains(got, "$GH_TOKEN") {
		t.Errorf("expected $GH_TOKEN reference in run script: %s", got)
	}
	if !strings.Contains(got, "$AWS_ACCESS_KEY_ID") {
		t.Errorf("expected $AWS_ACCESS_KEY_ID reference in run script: %s", got)
	}
	// Env block created with secrets context.
	if !strings.Contains(got, "GH_TOKEN: ${{ secrets.GH_TOKEN }}") {
		t.Errorf("expected GH_TOKEN env mapping in step env: %s", got)
	}
	if !strings.Contains(got, "AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}") {
		t.Errorf("expected AWS_ACCESS_KEY_ID env mapping in step env: %s", got)
	}
}

func TestFixHardcodedSecretInRunMergesExistingEnv(t *testing.T) {
	// Step already has an env block with unrelated entries — the fixer should
	// add the hoisted entry without dropping the existing one.
	vulnerableYAML := `name: Test inline-script secret merge
on: push
permissions: read-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Push
        env:
          KEEP_ME: yes
        run: |
          curl -H "Authorization: token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" https://api.github.com/user
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if _, err := FixFile(filePath, findings); err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	updated, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	got := string(updated)

	if !strings.Contains(got, "KEEP_ME: yes") {
		t.Errorf("fixer dropped existing env entry: %s", got)
	}
	if !strings.Contains(got, "GH_TOKEN: ${{ secrets.GH_TOKEN }}") {
		t.Errorf("fixer did not add hoisted GH_TOKEN env entry: %s", got)
	}
}

func TestFixPPE(t *testing.T) {
	vulnerableYAML := `name: Test PPE
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run script
        run: |
          echo "Processing PR: ${{ github.event.pull_request.title }}"
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	// Verify that the run command has $PR_TITLE
	if !strings.Contains(string(updatedContent), "Processing PR: $PR_TITLE") {
		t.Errorf("updated content does not reference environment variable in run: %s", string(updatedContent))
	}
	// Verify that the env block was injected
	if !strings.Contains(string(updatedContent), "PR_TITLE: ${{ github.event.pull_request.title }}") {
		t.Errorf("updated content does not define PR_TITLE in env: %s", string(updatedContent))
	}
}

// TestFixPPEHeadRef confirms the run-script env-hoist fix also covers the
// newly-detected github.head_ref interpolation.
func TestFixPPEHeadRef(t *testing.T) {
	yamlIn := `name: Test PPE head_ref
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "branch ${{ github.head_ref }}"
`
	out, fixes, err := FixBytes([]byte(yamlIn), mustScanBytes(t, "ci.yml", yamlIn))
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if fixes < 1 {
		t.Fatalf("expected at least 1 fix, got %d", fixes)
	}
	if !strings.Contains(string(out), "$GITHUB_HEAD_REF") {
		t.Errorf("run script not rewritten to env var: %s", out)
	}
	if !strings.Contains(string(out), "GITHUB_HEAD_REF: ${{ github.head_ref }}") {
		t.Errorf("env block not injected: %s", out)
	}
}

// TestFixPPEWithInputNotFixed confirms a PPE finding anchored on an action
// with:-input value is flag-only: the fixer must not mangle the workflow by
// hoisting into the with: block.
func TestFixPPEWithInputNotFixed(t *testing.T) {
	yamlIn := `name: github-script injection
on: issue_comment
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
`
	// Isolate the PPE finding so other (legitimately fixable) findings in the
	// same workflow don't mask the assertion.
	var ppe []Finding
	for _, f := range mustScanBytes(t, "ci.yml", yamlIn) {
		if f.RuleID == RulePPEShellInjection {
			ppe = append(ppe, f)
		}
	}
	if len(ppe) != 1 {
		t.Fatalf("expected exactly 1 PPE finding to fix, got %d", len(ppe))
	}
	out, fixes, err := FixBytes([]byte(yamlIn), ppe)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if fixes != 0 || out != nil {
		t.Errorf("with:-input PPE finding must not be auto-fixed, got %d fixes / out=%q", fixes, out)
	}
}

func mustScanBytes(t *testing.T, name, content string) []Finding {
	t.Helper()
	findings, err := ScanBytes(name, []byte(content))
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	return findings
}

func TestFixDebugLogging(t *testing.T) {
	vulnerableYAML := `name: Test debug logging
on: push
permissions: read-all
env:
  ACTIONS_STEP_DEBUG: true
  OTHER_FLAG: keep-me
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - run: echo hi
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	newFindings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("re-scan failed: %v", err)
	}
	for _, f := range newFindings {
		if f.Category == "CICD-SEC-7" {
			t.Errorf("expected CICD-SEC-7 to be fixed, still found: %+v", f)
		}
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if strings.Contains(string(updatedContent), "ACTIONS_STEP_DEBUG") {
		t.Errorf("updated content still contains ACTIONS_STEP_DEBUG: %s", string(updatedContent))
	}
	if !strings.Contains(string(updatedContent), "OTHER_FLAG: keep-me") {
		t.Errorf("fixer dropped sibling env entry: %s", string(updatedContent))
	}
}

func TestFixContinueOnErrorJob(t *testing.T) {
	vulnerableYAML := `name: Test continue-on-error
on: push
permissions: read-all
jobs:
  flaky:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    continue-on-error: true
    steps:
      - run: false
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	newFindings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("re-scan failed: %v", err)
	}
	for _, f := range newFindings {
		if f.Category == "CICD-SEC-10" {
			t.Errorf("expected CICD-SEC-10 to be fixed, still found: %+v", f)
		}
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if strings.Contains(string(updatedContent), "continue-on-error: true") {
		t.Errorf("updated content still contains continue-on-error: true: %s", string(updatedContent))
	}
}

func TestFixSLSAPermsOverlyBroad(t *testing.T) {
	vulnerableYAML := `name: Test perms overly broad
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions: read-all
    steps:
      - run: echo hi
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	newFindings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("re-scan failed: %v", err)
	}
	for _, f := range newFindings {
		if f.RuleID == RuleSLSAPermsOverlyBroad {
			t.Errorf("expected perms-overly-broad to be fixed, still found: %+v", f)
		}
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if strings.Contains(string(updatedContent), "write-all") {
		t.Errorf("updated content still contains write-all: %s", string(updatedContent))
	}
	if !strings.Contains(string(updatedContent), "permissions: read-all") {
		t.Errorf("updated content missing replacement read-all: %s", string(updatedContent))
	}
}

func TestFixSLSAOIDCTokenScope(t *testing.T) {
	vulnerableYAML := `name: Test OIDC scope
on: push
permissions: read-all
jobs:
  sign:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: sigstore/cosign-installer@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: cosign sign-blob foo.tar.gz
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	fixes, err := FixFile(filePath, findings)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if fixes < 1 {
		t.Errorf("expected at least 1 fix, got %d", fixes)
	}

	newFindings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("re-scan failed: %v", err)
	}
	for _, f := range newFindings {
		if f.RuleID == RuleSLSAOIDCTokenScope {
			t.Errorf("expected OIDC scope to be fixed, still found: %+v", f)
		}
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if !strings.Contains(string(updatedContent), "id-token: write") {
		t.Errorf("updated content missing id-token: write: %s", string(updatedContent))
	}
}

func TestFixSLSAOIDCTokenScopeExistingPermissions(t *testing.T) {
	// Job already has a permissions mapping — the fixer should merge id-token: write
	// in rather than overwriting other scopes the user already declared.
	vulnerableYAML := `name: Test OIDC scope merge
on: push
permissions: read-all
jobs:
  sign:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: write
    steps:
      - uses: sigstore/cosign-installer@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: cosign sign-blob foo.tar.gz
`
	filePath := createTempFile(t, vulnerableYAML)
	defer os.Remove(filePath)

	findings, err := ScanFile(filePath)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if _, err := FixFile(filePath, findings); err != nil {
		t.Fatalf("fix failed: %v", err)
	}

	updatedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}
	if !strings.Contains(string(updatedContent), "contents: write") {
		t.Errorf("fixer dropped existing contents: write scope: %s", string(updatedContent))
	}
	if !strings.Contains(string(updatedContent), "id-token: write") {
		t.Errorf("fixer did not add id-token: write: %s", string(updatedContent))
	}
}

// TestFixCheckoutPersistCredentials confirms the checkout-persist-credentials
// rule auto-fixes by adding persist-credentials: false to the with: block.
func TestFixCheckoutPersistCredentials(t *testing.T) {
	yamlIn := `name: persist creds
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	var persist []Finding
	for _, f := range mustScanBytes(t, "ci.yml", yamlIn) {
		if f.RuleID == RuleCheckoutPersistCreds {
			persist = append(persist, f)
		}
	}
	if len(persist) != 1 {
		t.Fatalf("expected 1 persist-credentials finding, got %d", len(persist))
	}
	out, fixes, err := FixBytes([]byte(yamlIn), persist)
	if err != nil {
		t.Fatalf("fix failed: %v", err)
	}
	if fixes != 1 {
		t.Fatalf("expected 1 fix, got %d", fixes)
	}
	if !strings.Contains(string(out), "persist-credentials: false") {
		t.Errorf("expected persist-credentials: false in output:\n%s", out)
	}
	// The fixed workflow must no longer trip the rule.
	for _, f := range mustScanBytes(t, "ci.yml", string(out)) {
		if f.RuleID == RuleCheckoutPersistCreds {
			t.Errorf("rule still fires after fix:\n%s", out)
		}
	}
}
