package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitHubPinAuditor_ResolveRef(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/commits/v4"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"sha":"abc123"}`))
		case strings.HasSuffix(r.URL.Path, "/commits/deadbeef"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	oldBase := githubAPIBaseURL
	githubAPIBaseURL = ts.URL
	defer func() { githubAPIBaseURL = oldBase }()

	auditor := NewGitHubPinAuditor("")

	sha, found, err := auditor.ResolveRef(context.Background(), "actions", "checkout", "v4")
	if err != nil || !found || sha != "abc123" {
		t.Errorf("ResolveRef(v4) = %q,%v,%v; want abc123,true,nil", sha, found, err)
	}

	_, found, err = auditor.ResolveRef(context.Background(), "actions", "checkout", "deadbeef")
	if err != nil || found {
		t.Errorf("ResolveRef(deadbeef) found=%v err=%v; want found=false, nil err", found, err)
	}
}

func TestGitHubPinAuditor_Advisories(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/advisories") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("ecosystem") != "actions" || r.URL.Query().Get("affects") != "some-org/some-action" {
			t.Errorf("unexpected advisories query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		// first_patched_version as a bare string (one of the two shapes).
		w.Write([]byte(`[
			{"ghsa_id":"GHSA-aaaa","summary":"RCE","vulnerabilities":[
				{"package":{"ecosystem":"actions","name":"some-org/some-action"},"vulnerable_version_range":"< 1.2.3","first_patched_version":"1.2.3"},
				{"package":{"ecosystem":"npm","name":"unrelated"},"vulnerable_version_range":"< 9.9.9","first_patched_version":"9.9.9"}
			]}
		]`))
	}))
	defer ts.Close()

	oldBase := githubAPIBaseURL
	githubAPIBaseURL = ts.URL
	defer func() { githubAPIBaseURL = oldBase }()

	advs, err := NewGitHubPinAuditor("tok").Advisories(context.Background(), "some-org", "some-action")
	if err != nil {
		t.Fatalf("Advisories error: %v", err)
	}
	// Only the actions-ecosystem package for this repo is kept.
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1: %+v", len(advs), advs)
	}
	if advs[0].GHSAID != "GHSA-aaaa" || advs[0].VulnerableRange != "< 1.2.3" || advs[0].FirstPatched != "1.2.3" {
		t.Errorf("unexpected advisory: %+v", advs[0])
	}
}

func TestParseFirstPatched(t *testing.T) {
	cases := map[string]string{
		`"1.2.3"`:                "1.2.3",
		`{"identifier":"2.0.0"}`: "2.0.0",
		`null`:                   "",
		``:                       "",
	}
	for in, want := range cases {
		if got := parseFirstPatched([]byte(in)); got != want {
			t.Errorf("parseFirstPatched(%q) = %q, want %q", in, got, want)
		}
	}
}
