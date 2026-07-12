package vcs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// --- workflowFixMock ------------------------------------------------------
//
// A configurable mock GitHub server that records every request so tests can
// assert on the exact PUT/POST bodies and verify the 5-step dance happens in
// the expected order. Smaller in scope than testhelpers' mockGitHub — this
// one targets just the endpoints workflow_fixer touches.

type workflowFixMock struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  []recordedRequest

	// Configurable behavior.
	fileBranch    string // ref the test wants the file to be served for; "" = any
	fileContent   []byte
	fileSHA       string
	fileBranchSHA string // file SHA on the *fix* branch after PUT; defaults to ""

	branchHeadSHA string // base branch HEAD; default "basesha"
	refExists     bool   // when true, POST /git/refs returns 422
	prExists      bool   // when true, POST /pulls returns 422 and GET /pulls?head=... returns one row
	existingPRURL string
	existingPRNum int
}

func newWorkflowFixMock(t *testing.T) *workflowFixMock {
	t.Helper()
	m := &workflowFixMock{
		branchHeadSHA: "basesha",
		existingPRURL: "https://github.com/acme/widgets/pull/77",
		existingPRNum: 77,
	}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.calls = append(m.calls, recordedRequest{Method: r.Method, Path: r.URL.Path, Body: body})
		m.mu.Unlock()

		switch {
		// GET /repos/{o}/{r}/contents/{path}?ref=...
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			// If the test pinned fileBranch, only respond for that ref. The
			// "branch SHA" path (fetch on fix branch) returns 404 by default
			// unless the test wants a hit there.
			ref := r.URL.Query().Get("ref")
			if m.fileBranch != "" && ref != m.fileBranch {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not found"}`))
				return
			}
			content := m.fileContent
			sha := m.fileSHA
			// If the test wants a different SHA for the fix branch (i.e. file
			// already exists on the branch from a prior click), use that.
			if strings.HasPrefix(ref, "pipefort/fix/") && m.fileBranchSHA != "" {
				sha = m.fileBranchSHA
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sha":      sha,
				"content":  base64.StdEncoding.EncodeToString(content),
				"encoding": "base64",
			})

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))

		// GET /repos/.../git/ref/heads/{branch}  → base branch HEAD lookup
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": map[string]string{"sha": m.branchHeadSHA},
			})

		// POST /repos/.../git/refs  → create branch
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			if m.refExists {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"message":"Reference already exists"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))

		// GET /repos/.../pulls?...  → list PRs by head
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls"):
			if m.prExists {
				_ = json.NewEncoder(w).Encode([]map[string]any{{
					"html_url": m.existingPRURL,
					"number":   m.existingPRNum,
				}})
				return
			}
			_, _ = w.Write([]byte(`[]`))

		// POST /repos/.../pulls  → open PR
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			if m.prExists {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"message":"A pull request already exists"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"html_url": "https://github.com/acme/widgets/pull/42",
				"number":   42,
			})

		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *workflowFixMock) callsByMethod(method string) []recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []recordedRequest
	for _, c := range m.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// --- Fixtures -------------------------------------------------------------

// vulnerableMissingPermissions hits the CICD-SEC-5 fixer: no top-level
// permissions and no per-job permissions either.
const vulnerableMissingPermissions = `name: test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`

// --- Happy path ----------------------------------------------------------

func TestFixWorkflowFile_HappyPath(t *testing.T) {
	mock := newWorkflowFixMock(t)
	mock.fileContent = []byte(vulnerableMissingPermissions)
	mock.fileSHA = "blobsha"
	mock.fileBranch = "main"

	c := newTestGitHubClient(t, mock.server.URL)
	res, err := c.FixWorkflowFile(
		context.Background(),
		"tok", "acme", "widgets", "main",
		".github/workflows/ci.yml",
		scanner.RuleMissingPermissions,
	)
	if err != nil {
		t.Fatalf("FixWorkflowFile: %v", err)
	}
	if res.URL != "https://github.com/acme/widgets/pull/42" || res.Number != 42 {
		t.Errorf("unexpected PR URL/number: %+v", res)
	}
	if res.Provider != ProviderGitHub {
		t.Errorf("expected provider github, got %q", res.Provider)
	}
	if res.FixesApplied != 1 {
		t.Errorf("expected 1 fix applied, got %d", res.FixesApplied)
	}
	if res.Reused {
		t.Error("expected fresh PR, got reused=true")
	}
	if !strings.HasPrefix(res.BranchName, "pipefort/fix/cicd-sec-5-missing-permissions/") {
		t.Errorf("unexpected branch name %q", res.BranchName)
	}

	// Verify the 4 mutating calls happened in order: branch create, file PUT,
	// PR create. (The first GET is the file fetch on main, plus a head SHA
	// lookup and a file fetch on the new branch.)
	posts := mock.callsByMethod(http.MethodPost)
	if len(posts) != 2 {
		t.Errorf("expected 2 POSTs (ref + pull), got %d: %+v", len(posts), posts)
	}
	puts := mock.callsByMethod(http.MethodPut)
	if len(puts) != 1 {
		t.Errorf("expected 1 PUT (file contents), got %d", len(puts))
	}

	// PUT body should contain the base64-encoded fixed content (which now
	// includes "permissions: read-all").
	var putBody map[string]string
	_ = json.Unmarshal(puts[0].Body, &putBody)
	decoded, _ := base64.StdEncoding.DecodeString(putBody["content"])
	if !strings.Contains(string(decoded), "permissions: read-all") {
		t.Errorf("PUT content missing the fix:\n%s", string(decoded))
	}
	if putBody["branch"] != res.BranchName {
		t.Errorf("PUT branch %q != res.BranchName %q", putBody["branch"], res.BranchName)
	}
}

// --- No-change (file is already clean) ------------------------------------

func TestFixWorkflowFile_NoChange(t *testing.T) {
	// A workflow that already has permissions: read-all — the CICD-SEC-5
	// fixer should find nothing to do and return ErrWorkflowFixNoChange.
	const clean = `name: test
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	mock := newWorkflowFixMock(t)
	mock.fileContent = []byte(clean)
	mock.fileSHA = "blobsha"
	mock.fileBranch = "main"

	c := newTestGitHubClient(t, mock.server.URL)
	res, err := c.FixWorkflowFile(
		context.Background(),
		"tok", "acme", "widgets", "main",
		".github/workflows/ci.yml",
		scanner.RuleMissingPermissions,
	)
	if err == nil {
		t.Fatal("expected ErrChangeRequestNoChange")
	}
	if err != ErrChangeRequestNoChange {
		t.Errorf("unexpected error: %v", err)
	}
	if !res.NoChange {
		t.Error("expected res.NoChange=true")
	}
	// No mutations should have been issued.
	if len(mock.callsByMethod(http.MethodPut))+len(mock.callsByMethod(http.MethodPost)) != 0 {
		t.Errorf("expected zero writes when no change, got PUTs=%d POSTs=%d",
			len(mock.callsByMethod(http.MethodPut)), len(mock.callsByMethod(http.MethodPost)))
	}
}

// --- Existing branch (422 on ref create is idempotent) -------------------

func TestFixWorkflowFile_ExistingBranchIsIdempotent(t *testing.T) {
	mock := newWorkflowFixMock(t)
	mock.fileContent = []byte(vulnerableMissingPermissions)
	mock.fileSHA = "blobsha"
	mock.fileBranch = "main"
	mock.refExists = true // POST /git/refs returns 422

	c := newTestGitHubClient(t, mock.server.URL)
	res, err := c.FixWorkflowFile(
		context.Background(),
		"tok", "acme", "widgets", "main",
		".github/workflows/ci.yml",
		scanner.RuleMissingPermissions,
	)
	if err != nil {
		t.Fatalf("expected idempotent success on existing branch, got %v", err)
	}
	if res.URL == "" {
		t.Error("expected a PR URL")
	}
}

// --- Existing PR (422 on pull create returns existing one) ---------------

func TestFixWorkflowFile_ExistingPRReused(t *testing.T) {
	mock := newWorkflowFixMock(t)
	mock.fileContent = []byte(vulnerableMissingPermissions)
	mock.fileSHA = "blobsha"
	mock.fileBranch = "main"
	mock.prExists = true

	c := newTestGitHubClient(t, mock.server.URL)
	res, err := c.FixWorkflowFile(
		context.Background(),
		"tok", "acme", "widgets", "main",
		".github/workflows/ci.yml",
		scanner.RuleMissingPermissions,
	)
	if err != nil {
		t.Fatalf("expected reuse of existing PR, got %v", err)
	}
	if !res.Reused {
		t.Error("expected Reused=true")
	}
	if res.URL != mock.existingPRURL {
		t.Errorf("expected reused PR URL %q, got %q", mock.existingPRURL, res.URL)
	}
	if res.Number != mock.existingPRNum {
		t.Errorf("expected reused PR number %d, got %d", mock.existingPRNum, res.Number)
	}
}

// --- Rule not in the fixable set -----------------------------------------

func TestFixWorkflowFile_RuleNotFixable(t *testing.T) {
	mock := newWorkflowFixMock(t)
	c := newTestGitHubClient(t, mock.server.URL)

	_, err := c.FixWorkflowFile(
		context.Background(),
		"tok", "acme", "widgets", "main",
		".github/workflows/ci.yml",
		scanner.RuleID("nope"),
	)
	if err == nil {
		t.Fatal("expected error for unknown rule")
	}
	if len(mock.callsByMethod(http.MethodGet))+len(mock.callsByMethod(http.MethodPost)) != 0 {
		t.Error("expected zero API calls for unfixable rule")
	}
}

// --- IsAutoFixableWorkflowRule / AutoFixableWorkflowRules ----------------

func TestIsAutoFixableWorkflowRule(t *testing.T) {
	cases := map[scanner.RuleID]bool{
		scanner.RuleMissingPermissions: true,
		scanner.RuleHardcodedSecrets:   true,
		scanner.RuleSLSAOIDCTokenScope: true,
		scanner.RuleSelfHostedRunners:  false, // no fixer for this
		scanner.RulePipeToShell:        false,
		scanner.RuleID("nonsense"):     false,
		scanner.RuleWPermWrite:         false, // repo-settings, not workflow
	}
	for rid, want := range cases {
		if got := IsAutoFixableWorkflowRule(rid); got != want {
			t.Errorf("IsAutoFixableWorkflowRule(%q) = %v, want %v", rid, got, want)
		}
	}
}

func TestAutoFixableWorkflowRulesIsSortedAndComplete(t *testing.T) {
	rules := AutoFixableWorkflowRules()
	// 12 GitHub Actions fixers + 3 GitLab CI fixers (debug-trace,
	// allow-failure, missing-timeout). Bump this count when adding new
	// platform-specific fixers and confirm the SPA picks them up too.
	if len(rules) != 15 {
		t.Errorf("expected 15 fixable workflow rules, got %d", len(rules))
	}
	for i := 1; i < len(rules); i++ {
		if rules[i-1] >= rules[i] {
			t.Errorf("rules not sorted: %v", rules)
			break
		}
	}
}

// --- assertion helpers ---------------------------------------------------

// (Mirrors the recordedRequest type from settings_fixer_test.go via the
// shared mockResponse type. Kept here for clarity in case those tests move.)
var _ = fmt.Sprintf
