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

// --- recordingMock --------------------------------------------------------
//
// recordingMock is a focused httptest server for the settings fixer. Unlike
// the broader mockGitHub in testhelpers_test.go (which only handles GETs and
// targets the scanner audit), this records mutating requests so tests can
// assert on method/path/body sent.

type recordedRequest struct {
	Method string
	Path   string
	Body   []byte
}

type recordingMock struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  []recordedRequest

	// Per-path GET responses (status + body). Default: 200 + empty.
	getResponses map[string]mockResponse
}

type mockResponse struct {
	status int
	body   []byte
}

func newRecordingMock(t *testing.T) *recordingMock {
	t.Helper()
	m := &recordingMock{getResponses: map[string]mockResponse{}}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.calls = append(m.calls, recordedRequest{Method: r.Method, Path: r.URL.Path, Body: body})
		m.mu.Unlock()

		if r.Method == http.MethodGet {
			if resp, ok := m.getResponses[r.URL.Path]; ok {
				if resp.status != 0 {
					w.WriteHeader(resp.status)
				}
				_, _ = w.Write(resp.body)
				return
			}
			// Default: 200 with empty body so JSON decode doesn't fail.
			_, _ = w.Write([]byte(`{}`))
			return
		}
		// Mutating verbs: default to 204 (matches Dependabot endpoints) or 200.
		switch r.Method {
		case http.MethodPut, http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *recordingMock) callsByMethod(method string) []recordedRequest {
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

func (m *recordingMock) setGet(path string, status int, body string) {
	m.getResponses[path] = mockResponse{status: status, body: []byte(body)}
}

// --- Tier 1 tests ----------------------------------------------------------

func TestFixWPermWrite_FetchesThenPuts(t *testing.T) {
	mock := newRecordingMock(t)
	mock.setGet("/repos/acme/widgets/actions/permissions/workflow", 200,
		`{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": true}`)

	c := newTestGitHubClient(t, mock.server.URL)
	action, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleWPermWrite, false)
	if err != nil {
		t.Fatalf("fix returned error: %v", err)
	}
	if !strings.Contains(action.Description, "read") {
		t.Errorf("description should mention read-only outcome, got %q", action.Description)
	}

	puts := mock.callsByMethod(http.MethodPut)
	if len(puts) != 1 {
		t.Fatalf("expected 1 PUT, got %d", len(puts))
	}
	var sent workflowPermsBody
	if err := json.Unmarshal(puts[0].Body, &sent); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	if sent.DefaultWorkflowPermissions != "read" {
		t.Errorf("expected default_workflow_permissions=read, got %q", sent.DefaultWorkflowPermissions)
	}
	if sent.CanApprovePullRequestReviews != true {
		t.Errorf("expected can_approve_pull_request_reviews=true preserved from GET, got %v", sent.CanApprovePullRequestReviews)
	}
}

func TestFixWPermPRApprove_PreservesDefaultPermissions(t *testing.T) {
	mock := newRecordingMock(t)
	mock.setGet("/repos/acme/widgets/actions/permissions/workflow", 200,
		`{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": true}`)

	c := newTestGitHubClient(t, mock.server.URL)
	if _, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleWPermPRApprove, false); err != nil {
		t.Fatalf("fix: %v", err)
	}

	puts := mock.callsByMethod(http.MethodPut)
	if len(puts) != 1 {
		t.Fatalf("expected 1 PUT, got %d", len(puts))
	}
	var sent workflowPermsBody
	_ = json.Unmarshal(puts[0].Body, &sent)
	if sent.CanApprovePullRequestReviews != false {
		t.Errorf("expected can_approve=false, got %v", sent.CanApprovePullRequestReviews)
	}
	if sent.DefaultWorkflowPermissions != "read" {
		t.Errorf("expected default_workflow_permissions=read preserved from GET, got %q", sent.DefaultWorkflowPermissions)
	}
}

func TestFixDependabotAlerts_PutsToCorrectPath(t *testing.T) {
	mock := newRecordingMock(t)
	c := newTestGitHubClient(t, mock.server.URL)

	if _, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleDependabotAlertsOff, false); err != nil {
		t.Fatalf("fix: %v", err)
	}
	puts := mock.callsByMethod(http.MethodPut)
	if len(puts) != 1 || puts[0].Path != "/repos/acme/widgets/vulnerability-alerts" {
		t.Fatalf("expected PUT /repos/acme/widgets/vulnerability-alerts, got %+v", puts)
	}
}

func TestFixSecretScanning_PatchesSecAnalysis(t *testing.T) {
	mock := newRecordingMock(t)
	c := newTestGitHubClient(t, mock.server.URL)

	if _, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleSecretScanningOff, false); err != nil {
		t.Fatalf("fix: %v", err)
	}
	patches := mock.callsByMethod(http.MethodPatch)
	if len(patches) != 1 || patches[0].Path != "/repos/acme/widgets" {
		t.Fatalf("expected PATCH /repos/acme/widgets, got %+v", patches)
	}
	var body secAnalysisBody
	_ = json.Unmarshal(patches[0].Body, &body)
	if body.SecurityAndAnalysis.SecretScanning == nil || body.SecurityAndAnalysis.SecretScanning.Status != "enabled" {
		t.Errorf("expected secret_scanning.status=enabled, got %+v", body)
	}
	if body.SecurityAndAnalysis.SecretScanningPushProtection != nil {
		t.Errorf("fix should not touch push protection: %+v", body)
	}
}

// --- Tier 2 tests ----------------------------------------------------------

func TestFixBPMissing_PutsDefaultProtection(t *testing.T) {
	mock := newRecordingMock(t)
	c := newTestGitHubClient(t, mock.server.URL)

	if _, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleBPMissing, false); err != nil {
		t.Fatalf("fix: %v", err)
	}
	puts := mock.callsByMethod(http.MethodPut)
	if len(puts) != 1 || puts[0].Path != "/repos/acme/widgets/branches/main/protection" {
		t.Fatalf("expected PUT branch protection, got %+v", puts)
	}
	var body bpPutBody
	_ = json.Unmarshal(puts[0].Body, &body)
	if !body.EnforceAdmins {
		t.Errorf("expected enforce_admins=true: %+v", body)
	}
	if body.RequiredPullRequestReviews == nil || body.RequiredPullRequestReviews.RequiredApprovingReviewCount != 2 {
		t.Errorf("expected 2 required reviews: %+v", body)
	}
	if body.AllowForcePushes == nil || *body.AllowForcePushes != false {
		t.Errorf("expected allow_force_pushes=false: %+v", body)
	}
}

func TestFixBPForcePush_PreservesOtherFields(t *testing.T) {
	mock := newRecordingMock(t)
	mock.setGet("/repos/acme/widgets/branches/main/protection", 200, `{
		"enforce_admins": {"enabled": true},
		"required_pull_request_reviews": {
			"dismiss_stale_reviews": true,
			"require_code_owner_reviews": true,
			"required_approving_review_count": 3
		},
		"required_status_checks": {"strict": true, "contexts": ["build"]},
		"allow_force_pushes": {"enabled": true},
		"allow_deletions": {"enabled": false}
	}`)

	c := newTestGitHubClient(t, mock.server.URL)
	if _, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleBPForcePush, false); err != nil {
		t.Fatalf("fix: %v", err)
	}

	puts := mock.callsByMethod(http.MethodPut)
	if len(puts) != 1 {
		t.Fatalf("expected 1 PUT, got %d", len(puts))
	}
	var body bpPutBody
	_ = json.Unmarshal(puts[0].Body, &body)

	// The field we changed:
	if body.AllowForcePushes == nil || *body.AllowForcePushes != false {
		t.Errorf("expected allow_force_pushes=false, got %+v", body.AllowForcePushes)
	}
	// Fields that must be preserved from the GET:
	if body.RequiredPullRequestReviews == nil || body.RequiredPullRequestReviews.RequiredApprovingReviewCount != 3 {
		t.Errorf("required_approving_review_count must be preserved: %+v", body.RequiredPullRequestReviews)
	}
	if !body.EnforceAdmins {
		t.Errorf("enforce_admins must be preserved")
	}
	if body.RequiredStatusChecks == nil || len(body.RequiredStatusChecks.Contexts) != 1 || body.RequiredStatusChecks.Contexts[0] != "build" {
		t.Errorf("required_status_checks must be preserved: %+v", body.RequiredStatusChecks)
	}
}

func TestFixBPForcePush_NoProtection_ReturnsError(t *testing.T) {
	mock := newRecordingMock(t)
	mock.setGet("/repos/acme/widgets/branches/main/protection", 404, `{"message":"Branch not protected"}`)

	c := newTestGitHubClient(t, mock.server.URL)
	if _, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleBPForcePush, false); err == nil {
		t.Fatal("expected error when branch protection doesn't exist")
	}
}

func TestFixBPNoSignedCommits_PostsRequiredSignatures(t *testing.T) {
	mock := newRecordingMock(t)
	c := newTestGitHubClient(t, mock.server.URL)

	if _, err := c.FixSingleRepositorySetting(context.Background(), "tok", "acme", "widgets", "main", scanner.RuleBPNoSignedCommits, false); err != nil {
		t.Fatalf("fix: %v", err)
	}
	posts := mock.callsByMethod(http.MethodPost)
	if len(posts) != 1 || !strings.HasSuffix(posts[0].Path, "/protection/required_signatures") {
		t.Fatalf("expected POST .../protection/required_signatures, got %+v", posts)
	}
}

// --- Dispatcher tests ------------------------------------------------------

func TestFixRepositorySettings_DispatchesByRuleID(t *testing.T) {
	mock := newRecordingMock(t)
	mock.setGet("/repos/acme/widgets/actions/permissions/workflow", 200,
		`{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": true}`)

	c := newTestGitHubClient(t, mock.server.URL)
	findings := []scanner.Finding{
		{RuleID: scanner.RuleWPermWrite},
		{RuleID: scanner.RuleSecretScanningOff},
		{RuleID: scanner.RuleDependabotAlertsOff},
		{RuleID: scanner.RuleBPNoStatusChecks}, // not auto-fixable
	}
	result := c.FixRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", findings, false)

	if len(result.Applied) != 3 {
		t.Errorf("expected 3 applied, got %d (%+v)", len(result.Applied), result.Applied)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != scanner.RuleBPNoStatusChecks {
		t.Errorf("expected 1 skipped (no-status-checks), got %+v", result.Skipped)
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %+v", result.Errors)
	}
}

func TestFixRepositorySettings_Deduplicates(t *testing.T) {
	mock := newRecordingMock(t)
	c := newTestGitHubClient(t, mock.server.URL)

	// Same rule fired twice in the findings list — fixer should only apply it once.
	findings := []scanner.Finding{
		{RuleID: scanner.RuleDependabotAlertsOff},
		{RuleID: scanner.RuleDependabotAlertsOff},
	}
	result := c.FixRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", findings, false)
	if len(result.Applied) != 1 {
		t.Errorf("expected dedup to 1 applied, got %d", len(result.Applied))
	}
	if len(mock.callsByMethod(http.MethodPut)) != 1 {
		t.Errorf("expected 1 PUT to GitHub, got %d", len(mock.callsByMethod(http.MethodPut)))
	}
}

// --- Dry run --------------------------------------------------------------

func TestFixRepositorySettings_DryRunSkipsMutations(t *testing.T) {
	mock := newRecordingMock(t)
	mock.setGet("/repos/acme/widgets/actions/permissions/workflow", 200,
		`{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": true}`)

	c := newTestGitHubClient(t, mock.server.URL)
	findings := []scanner.Finding{
		{RuleID: scanner.RuleWPermWrite},
		{RuleID: scanner.RuleDependabotAlertsOff},
	}
	result := c.FixRepositorySettings(context.Background(), "tok", "acme", "widgets", "main", findings, true)

	if !result.DryRun {
		t.Error("expected DryRun=true in result")
	}
	if len(result.Applied) != 2 {
		t.Errorf("expected 2 would-be actions in dry-run, got %d", len(result.Applied))
	}
	// GETs are still issued so descriptions reflect the real current state, but
	// PUT/PATCH/POST must be intercepted before the network.
	if len(mock.callsByMethod(http.MethodPut)) != 0 {
		t.Errorf("dry-run should issue zero PUTs, got %d", len(mock.callsByMethod(http.MethodPut)))
	}
	if len(mock.callsByMethod(http.MethodPatch)) != 0 {
		t.Errorf("dry-run should issue zero PATCHes, got %d", len(mock.callsByMethod(http.MethodPatch)))
	}
}

// --- IsAutoFixableRepoSetting ---------------------------------------------

func TestIsAutoFixableRepoSetting(t *testing.T) {
	cases := map[scanner.RuleID]bool{
		scanner.RuleWPermWrite:        true,
		scanner.RuleBPMissing:         true,
		scanner.RuleBPForcePush:       true,
		scanner.RuleBPNoStatusChecks:  false, // intentionally not in the map
		scanner.RuleActionsAllAllowed: false, // deferred
		scanner.RuleID("nonsense"):    false,
	}
	for ruleID, want := range cases {
		if got := IsAutoFixableRepoSetting(ruleID); got != want {
			t.Errorf("IsAutoFixableRepoSetting(%q) = %v, want %v", ruleID, got, want)
		}
	}
}
