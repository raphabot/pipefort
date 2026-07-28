package vcs

import (
	"context"

	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// --- gitlabFixMock --------------------------------------------------------
//
// A configurable mock GitLab API covering the endpoints the MR remediation
// pipeline touches, recording every request so tests can assert the batched
// path produces exactly one commit and one MR.

type gitlabFixMock struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  []recordedRequest

	fileContent []byte
	fileMissing bool

	mrExists    bool
	existingURL string
	existingIID int
}

func newGitLabFixMock(t *testing.T) *gitlabFixMock {
	t.Helper()
	m := &gitlabFixMock{
		existingURL: "https://gitlab.com/acme/widgets/-/merge_requests/9",
		existingIID: 9,
	}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.calls = append(m.calls, recordedRequest{Method: r.Method, Path: r.URL.Path, Body: body})
		m.mu.Unlock()

		switch {
		// GET /projects/{id}/repository/files/{path}/raw?ref=... — serves the
		// file's raw bytes (not a base64 JSON envelope).
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/repository/files/"):
			if m.fileMissing {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"404 File Not Found"}`))
				return
			}
			_, _ = w.Write(m.fileContent)

		// POST /projects/{id}/repository/branches
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/repository/branches"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))

		// POST /projects/{id}/repository/commits
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/repository/commits"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))

		// GET /projects/{id}/merge_requests?source_branch=...
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/merge_requests"):
			if m.mrExists {
				_ = json.NewEncoder(w).Encode([]map[string]any{{
					"web_url": m.existingURL,
					"iid":     m.existingIID,
				}})
				return
			}
			_, _ = w.Write([]byte(`[]`))

		// POST /projects/{id}/merge_requests
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/merge_requests"):
			if m.mrExists {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":["Another open merge request already exists"]}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"web_url": "https://gitlab.com/acme/widgets/-/merge_requests/12",
				"iid":     12,
			})

		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *gitlabFixMock) countPosts(suffix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.Method == http.MethodPost && strings.HasSuffix(c.Path, suffix) {
			n++
		}
	}
	return n
}

func newTestGitLabClient(t *testing.T, baseURL string) *GitLabClient {
	t.Helper()
	return NewGitLabClient("gitlab.test", WithBaseURL(baseURL), WithHTTPClient(http.DefaultClient))
}

// glVulnerableCI trips three fixable GitLab rules: debug trace, allow_failure,
// and a missing job timeout.
const glVulnerableCI = `stages:
  - build
variables:
  CI_DEBUG_TRACE: "true"
build:
  stage: build
  allow_failure: true
  script:
    - echo hi
`

// --- Batched, file-scoped MR remediation ----------------------------------

func TestGitLabFixWorkflowFileRules_BatchesEveryRuleIntoOneMR(t *testing.T) {
	mock := newGitLabFixMock(t)
	mock.fileContent = []byte(glVulnerableCI)

	c := newTestGitLabClient(t, mock.server.URL)
	res, err := c.FixWorkflowRules(
		context.Background(),
		"tok",
		RepoCoord{Owner: "acme", Name: "widgets", ID: "1234"},
		"main",
		".gitlab-ci.yml",
		[]scanner.RuleID{
			scanner.RuleGitLabDebugTrace,
			scanner.RuleGitLabAllowFailure,
			scanner.RuleGitLabMissingTimeout,
		},
	)
	if err != nil {
		t.Fatalf("FixWorkflowRules: %v", err)
	}

	if res.Provider != ProviderGitLab {
		t.Errorf("provider = %q, want gitlab", res.Provider)
	}
	if res.URL != "https://gitlab.com/acme/widgets/-/merge_requests/12" || res.Number != 12 {
		t.Errorf("unexpected MR: %+v", res)
	}
	if want := "pipefort/fix/file/gitlab-ci-yml"; res.BranchName != want {
		t.Errorf("branch = %q, want %q", res.BranchName, want)
	}
	if res.FixesApplied != 3 {
		t.Errorf("FixesApplied = %d, want 3 (all rules in one commit)", res.FixesApplied)
	}
	if n := mock.countPosts("/repository/commits"); n != 1 {
		t.Errorf("expected exactly 1 commit, got %d", n)
	}
	if n := mock.countPosts("/merge_requests"); n != 1 {
		t.Errorf("expected exactly 1 MR opened, got %d", n)
	}
}

func TestGitLabFixWorkflowFileRules_ReusesExistingMR(t *testing.T) {
	mock := newGitLabFixMock(t)
	mock.fileContent = []byte(glVulnerableCI)
	mock.mrExists = true

	c := newTestGitLabClient(t, mock.server.URL)
	res, err := c.FixWorkflowRules(
		context.Background(),
		"tok",
		RepoCoord{Owner: "acme", Name: "widgets", ID: "1234"},
		"main",
		".gitlab-ci.yml",
		[]scanner.RuleID{scanner.RuleGitLabDebugTrace, scanner.RuleGitLabAllowFailure},
	)
	if err != nil {
		t.Fatalf("FixWorkflowRules: %v", err)
	}
	if !res.Reused || res.URL != mock.existingURL {
		t.Errorf("expected the existing MR to be reused, got %+v", res)
	}
}

// The per-rule MR path must keep its own branch namespace so the per-finding
// Fix button is unaffected by batching.
func TestGitLabFixWorkflow_StillUsesPerRuleBranch(t *testing.T) {
	mock := newGitLabFixMock(t)
	mock.fileContent = []byte(glVulnerableCI)

	c := newTestGitLabClient(t, mock.server.URL)
	res, err := c.FixWorkflow(
		context.Background(),
		"tok",
		RepoCoord{Owner: "acme", Name: "widgets", ID: "1234"},
		"main",
		".gitlab-ci.yml",
		scanner.RuleGitLabDebugTrace,
	)
	if err != nil {
		t.Fatalf("FixWorkflow: %v", err)
	}
	if want := ChangeBranchName(scanner.RuleGitLabDebugTrace, ".gitlab-ci.yml"); res.BranchName != want {
		t.Errorf("branch = %q, want %q", res.BranchName, want)
	}
}
