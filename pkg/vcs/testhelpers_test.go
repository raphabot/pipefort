package vcs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- test RSA key + GitHub client -----------------------------------------

func generateTestKey(t *testing.T) (*rsaKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return &rsaKey{key: key}, string(pemBytes)
}

// newTestGitHubClient builds a client whose API base points at the given test
// server, signing app JWTs with a freshly generated key.
func newTestGitHubClient(t *testing.T, baseURL string) *GitHubClient {
	t.Helper()
	key, _ := generateTestKey(t)
	return &GitHubClient{
		appID:      "12345",
		privateKey: key,
		http:       http.DefaultClient,
		baseURL:    baseURL,
	}
}

// loadVulnerableWorkflow reads the shared fixture used across scanner-facing
// tests. The relative path resolves from pkg/vcs to the repo-root testdata dir.
func loadVulnerableWorkflow(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/vulnerable-workflow.yml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// --- mock GitHub API -------------------------------------------------------

// mockGitHub is a configurable httptest server emulating the GitHub endpoints
// the client touches. The settings-audit endpoints default to a "secure"
// repository — tests focused on workflow scanning don't have to wire them up,
// and tests focused on settings opt into vulnerability via the corresponding
// json.RawMessage fields.
type mockGitHub struct {
	server    *httptest.Server
	repos     []Repo
	tree      []treeNode
	blobs     map[string][]byte // sha -> raw content
	account   Installation
	tokenCode int // status to return for access_tokens (0 -> 201/200)

	// Settings-audit responses. nil RawMessage = use the secure default below.
	repoInfo           json.RawMessage  // GET /repos/{o}/{r} body
	repoStatus         int              // 0 -> 200; e.g. 403 to simulate missing perms
	branchProtection   json.RawMessage  // GET /branches/{b}/protection (nil -> 404)
	branchProtBody     string           // GET /branches/{b}/protection body when branchProtStatus is set
	branchProtStatus   int              // 0 -> normal; e.g. 403 to simulate a plan/permission error
	workflowPerms      json.RawMessage  // GET /actions/permissions/workflow
	actionsPermissions json.RawMessage  // GET /actions/permissions
	dependabotAlerts   bool             // true -> 204; false -> 404
	codeownersPaths    map[string]bool  // path (e.g. ".github/CODEOWNERS") -> exists
	repoConfig         []byte           // GET /contents/.pipefort.yml body (nil -> 404 on every candidate)
	ownerRepos         []Repo           // GET /orgs/{o}/repos and /users/{o}/repos (nil -> org 404, then user 404)
	prFiles            []string         // GET /pulls/{n}/files filenames
	checkRunStatus     int              // status for POST /check-runs (0 -> 201); e.g. 403 to simulate missing checks:write
	checkRuns          []map[string]any // captured POST /check-runs bodies
}

// secureRepoInfo is the default GET /repos/{o}/{r} body: nothing flagged,
// everything in security_and_analysis enabled.
var secureRepoInfo = json.RawMessage(`{
	"private": false,
	"visibility": "public",
	"default_branch": "main",
	"security_and_analysis": {
		"secret_scanning": {"status": "enabled"},
		"secret_scanning_push_protection": {"status": "enabled"},
		"dependabot_security_updates": {"status": "enabled"}
	}
}`)

// secureWorkflowPerms — default GITHUB_TOKEN is read-only, no PR approval.
var secureWorkflowPerms = json.RawMessage(`{
	"default_workflow_permissions": "read",
	"can_approve_pull_request_reviews": false
}`)

// secureActionsPermissions — Actions enabled, allowlist (not "all").
var secureActionsPermissions = json.RawMessage(`{
	"enabled": true,
	"allowed_actions": "selected"
}`)

// secureBranchProtection — every rule turned on, admins enforced, force-push
// and deletion blocked, signed commits required.
var secureBranchProtection = json.RawMessage(`{
	"enforce_admins": {"enabled": true},
	"required_pull_request_reviews": {
		"dismiss_stale_reviews": true,
		"require_code_owner_reviews": true,
		"required_approving_review_count": 2
	},
	"required_status_checks": {"strict": true},
	"required_signatures": {"enabled": true},
	"allow_force_pushes": {"enabled": false},
	"allow_deletions": {"enabled": false}
}`)

type treeNode struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int    `json:"size"`
}

func newMockGitHub(t *testing.T) *mockGitHub {
	// Defaults: a fully hardened repo (every settings rule passes). Tests
	// that want a vulnerability fire override one or more fields.
	m := &mockGitHub{
		blobs:            map[string][]byte{},
		branchProtection: secureBranchProtection,
		dependabotAlerts: true,
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		// /app/installations/{id}            -> installation metadata
		// /app/installations/{id}/access_tokens -> token
		if r.Method == http.MethodPost {
			if m.tokenCode != 0 {
				w.WriteHeader(m.tokenCode)
				_, _ = w.Write([]byte(`{"message":"boom"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_installationtoken"})
			return
		}
		_ = json.NewEncoder(w).Encode(m.account)
	})

	// Owner repo listing for the CLI org scan. /orgs/{o}/repos is tried first,
	// then /users/{o}/repos; serve the list on the user endpoint (exercising the
	// org→user fallback) and 404 the org endpoint.
	ownerReposHandler := func(serve bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !serve || m.ownerRepos == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Not Found"}`))
				return
			}
			page := r.URL.Query().Get("page")
			if page != "" && page != "1" {
				_ = json.NewEncoder(w).Encode([]Repo{})
				return
			}
			_ = json.NewEncoder(w).Encode(m.ownerRepos)
		}
	}
	mux.HandleFunc("/orgs/", ownerReposHandler(false))
	mux.HandleFunc("/users/", ownerReposHandler(true))

	mux.HandleFunc("/installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		// Single page is enough for tests; <100 results terminates pagination.
		page := r.URL.Query().Get("page")
		if page != "" && page != "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(m.repos), "repositories": []Repo{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(m.repos), "repositories": m.repos})
	})

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/git/trees/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"tree": m.tree})
		case strings.Contains(r.URL.Path, "/git/blobs/"):
			sha := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			raw, ok := m.blobs[sha]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not found"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString(raw),
				"encoding": "base64",
			})

		// --- pull-request check endpoints ---------------------------------
		case strings.Contains(r.URL.Path, "/pulls/") && strings.HasSuffix(r.URL.Path, "/files"):
			out := make([]map[string]string, 0, len(m.prFiles))
			for _, f := range m.prFiles {
				out = append(out, map[string]string{"filename": f})
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasSuffix(r.URL.Path, "/check-runs") && r.Method == http.MethodPost:
			if m.checkRunStatus != 0 {
				w.WriteHeader(m.checkRunStatus)
				_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
				return
			}
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			m.checkRuns = append(m.checkRuns, payload)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1})

		// --- repository-settings audit endpoints --------------------------
		case strings.Contains(r.URL.Path, "/branches/") && strings.HasSuffix(r.URL.Path, "/protection"):
			if m.branchProtStatus != 0 {
				w.WriteHeader(m.branchProtStatus)
				_, _ = w.Write([]byte(m.branchProtBody))
				return
			}
			if m.branchProtection == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Branch not protected"}`))
				return
			}
			_, _ = w.Write(m.branchProtection)
		case strings.HasSuffix(r.URL.Path, "/actions/permissions/workflow"):
			body := m.workflowPerms
			if body == nil {
				body = secureWorkflowPerms
			}
			_, _ = w.Write(body)
		case strings.HasSuffix(r.URL.Path, "/actions/permissions"):
			body := m.actionsPermissions
			if body == nil {
				body = secureActionsPermissions
			}
			_, _ = w.Write(body)
		case strings.HasSuffix(r.URL.Path, "/vulnerability-alerts"):
			if m.dependabotAlerts {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case strings.Contains(r.URL.Path, "/contents/"):
			rel := r.URL.Path[strings.Index(r.URL.Path, "/contents/")+len("/contents/"):]
			// .pipefort.yml config lookup (strip any ?ref= already handled by URL.Path).
			if m.repoConfig != nil && rel == ".pipefort.yml" {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"content":  base64.StdEncoding.EncodeToString(m.repoConfig),
					"encoding": "base64",
				})
				return
			}
			if m.codeownersPaths[rel] {
				_ = json.NewEncoder(w).Encode(map[string]string{"name": "CODEOWNERS", "path": rel})
				return
			}
			w.WriteHeader(http.StatusNotFound)

		// --- default: /repos/{owner}/{repo} -------------------------------
		default:
			if m.repoStatus != 0 {
				w.WriteHeader(m.repoStatus)
				_, _ = w.Write([]byte(`{"message":"forbidden"}`))
				return
			}
			body := m.repoInfo
			if body == nil {
				body = secureRepoInfo
			}
			_, _ = w.Write(body)
		}
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// addWorkflow registers a workflow blob in the tree under the given path.
func (m *mockGitHub) addWorkflow(path, sha string, content []byte) {
	m.tree = append(m.tree, treeNode{Path: path, Type: "blob", SHA: sha, Size: len(content)})
	m.blobs[sha] = content
}
