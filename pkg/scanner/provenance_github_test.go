package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// newProvenanceServer returns a verifier wired to an httptest server. This is
// possible only because BaseURL is exported — the pinned-action auditor's
// equivalent is package-private and its online pass therefore reaches the real
// api.github.com during tests.
func newProvenanceServer(t *testing.T, h http.HandlerFunc) *GitHubProvenanceVerifier {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &GitHubProvenanceVerifier{
		Token:           "test-token",
		Client:          srv.Client(),
		BaseURL:         srv.URL,
		TrustedMaterial: &root.BaseTrustedMaterial{},
	}
}

func TestLatestReleaseArtifactsParsesDigests(t *testing.T) {
	v := newProvenanceServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget/releases/latest" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
			t.Errorf("X-GitHub-Api-Version = %q", got)
		}
		fmt.Fprint(w, `{"tag_name":"v1.4.0","assets":[
			{"name":"widget-linux-amd64","digest":"sha256:aa"},
			{"name":"checksums.txt","digest":"sha256:bb"}]}`)
	})

	arts, err := v.LatestReleaseArtifacts(context.Background(), "acme", "widget")
	if err != nil {
		t.Fatalf("LatestReleaseArtifacts: %v", err)
	}
	if len(arts) != 2 {
		t.Fatalf("want 2 artifacts, got %d", len(arts))
	}
	if arts[0].ReleaseTag != "v1.4.0" || arts[0].AssetName != "widget-linux-amd64" || arts[0].Digest != "sha256:aa" {
		t.Errorf("artifact[0] = %+v", arts[0])
	}
	if arts[0].Owner != "acme" || arts[0].Repo != "widget" {
		t.Errorf("artifact[0] coordinates = %+v", arts[0])
	}
}

func TestLatestReleaseArtifactsNoReleaseIsNotAnError(t *testing.T) {
	// A repo with no releases must be silence, not a failure — the audit's
	// whole no-release guard depends on it.
	v := newProvenanceServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})
	arts, err := v.LatestReleaseArtifacts(context.Background(), "acme", "widget")
	if err != nil {
		t.Fatalf("404 must not be an error, got %v", err)
	}
	if len(arts) != 0 {
		t.Errorf("want no artifacts, got %+v", arts)
	}
}

func TestLatestReleaseArtifactsPropagatesRealErrors(t *testing.T) {
	// 403 is what a missing `attestations:read` permission looks like; the
	// caller has to be able to tell that apart from "no releases".
	v := newProvenanceServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Forbidden"}`, http.StatusForbidden)
	})
	if _, err := v.LatestReleaseArtifacts(context.Background(), "acme", "widget"); err == nil {
		t.Fatal("want an error for 403, got nil")
	}
}

func TestVerifyReportsMissingWhenNoAttestations(t *testing.T) {
	v := newProvenanceServer(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"attestations":[]}`)
	})
	res, err := v.Verify(context.Background(), asset("widget.tar.gz"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.State != ProvenanceMissing {
		t.Errorf("state = %q, want %q", res.State, ProvenanceMissing)
	}
}

func TestVerifyReportsMissingOn404(t *testing.T) {
	v := newProvenanceServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	})
	res, err := v.Verify(context.Background(), asset("widget.tar.gz"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.State != ProvenanceMissing {
		t.Errorf("state = %q, want %q", res.State, ProvenanceMissing)
	}
}

func TestVerifySendsPredicateTypeFilter(t *testing.T) {
	var gotQuery string
	v := newProvenanceServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"attestations":[]}`)
	})
	if _, err := v.Verify(context.Background(), asset("widget.tar.gz")); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !strings.Contains(gotQuery, "predicate_type=") || !strings.Contains(gotQuery, "slsa.dev%2Fprovenance%2Fv1") {
		t.Errorf("query = %q, want a slsa provenance predicate_type filter", gotQuery)
	}
}

func TestVerifyMalformedBundleIsUnverifiableNotAnError(t *testing.T) {
	// A broken bundle is a finding about the release, not a scanner failure.
	v := newProvenanceServer(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"attestations":[{"bundle":{"mediaType":"nonsense"}}]}`)
	})
	res, err := v.Verify(context.Background(), asset("widget.tar.gz"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.State != ProvenanceUnverifiable {
		t.Fatalf("state = %q, want %q", res.State, ProvenanceUnverifiable)
	}
	if res.Reason == "" {
		t.Error("an unverifiable verdict must carry a reason")
	}
}

func TestVerifyFollowsBundleURL(t *testing.T) {
	// GitHub returns a null inline bundle and a pre-signed storage URL, so the
	// bundle_url path is the only one that runs in production.
	for _, tc := range []struct {
		name      string
		crossHost bool
		wantAuth  string
	}{
		{
			// A pre-signed blob URL authenticates via its query string;
			// adding our own header makes the storage backend answer 401.
			name: "cross-host bundle gets no token", crossHost: true, wantAuth: "",
		},
		{
			// A GitHub Enterprise Server serving bundles from its own domain
			// does need the token.
			name: "same-host bundle keeps the token", crossHost: false, wantAuth: "Bearer test-token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fetched bool
			bundleMux := http.NewServeMux()
			bundleMux.HandleFunc("/bundle", func(w http.ResponseWriter, r *http.Request) {
				fetched = true
				if got := r.Header.Get("Authorization"); got != tc.wantAuth {
					t.Errorf("Authorization = %q, want %q", got, tc.wantAuth)
				}
				w.Header().Set("Content-Type", "application/x-snappy")
				w.Write(snappy.Encode(nil, []byte(`{"mediaType":"nonsense"}`)))
			})

			var bundleBase string
			apiMux := http.NewServeMux()
			api := httptest.NewServer(apiMux)
			t.Cleanup(api.Close)

			if tc.crossHost {
				bundleSrv := httptest.NewServer(bundleMux)
				t.Cleanup(bundleSrv.Close)
				bundleBase = bundleSrv.URL
			} else {
				apiMux.Handle("/bundle", bundleMux)
				bundleBase = api.URL
			}

			apiMux.HandleFunc("/repos/", func(w http.ResponseWriter, _ *http.Request) {
				body, _ := json.Marshal(map[string]any{
					"attestations": []map[string]any{{"bundle": nil, "bundle_url": bundleBase + "/bundle"}},
				})
				w.Write(body)
			})

			v := &GitHubProvenanceVerifier{
				Token:           "test-token",
				Client:          api.Client(),
				BaseURL:         api.URL,
				TrustedMaterial: &root.BaseTrustedMaterial{},
			}
			res, err := v.Verify(context.Background(), asset("widget.tar.gz"))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !fetched {
				t.Fatal("bundle_url was not followed")
			}
			// The stub bundle is well-formed JSON but not a real Sigstore
			// bundle, so it lands on unverifiable — which proves the snappy
			// payload was decoded and handed to the verifier.
			if res.State != ProvenanceUnverifiable {
				t.Errorf("state = %q, want %q", res.State, ProvenanceUnverifiable)
			}
		})
	}
}

func TestVerifyRejectsNonHexDigest(t *testing.T) {
	v := newProvenanceServer(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"attestations":[{"bundle":{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}}]}`)
	})
	a := asset("widget.tar.gz")
	a.Digest = "sha256:not-hex"
	res, err := v.Verify(context.Background(), a)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.State != ProvenanceUnverifiable || !strings.Contains(res.Reason, "hex") {
		t.Errorf("res = %+v, want an unverifiable hex-digest verdict", res)
	}
}

// TestVerifyLive exercises the real Sigstore path against a real repository.
// It is opt-in because it needs network access and TUF metadata; CI does not
// run it. Set PIPEFORT_LIVE_ATTESTATION=owner/repo to enable.
func TestVerifyLive(t *testing.T) {
	target := os.Getenv("PIPEFORT_LIVE_ATTESTATION")
	if target == "" {
		t.Skip("PIPEFORT_LIVE_ATTESTATION not set; skipping live Sigstore verification")
	}
	owner, repo, ok := strings.Cut(target, "/")
	if !ok {
		t.Fatalf("PIPEFORT_LIVE_ATTESTATION must be owner/repo, got %q", target)
	}

	v := NewGitHubProvenanceVerifier(os.Getenv("GITHUB_TOKEN"))
	findings, records, err := AuditReleaseProvenance(context.Background(), owner, repo, v)
	if err != nil {
		t.Fatalf("AuditReleaseProvenance: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("no artifacts verified for %s — check the repo publishes release assets", target)
	}
	for _, r := range records {
		t.Logf("%-40s %-14s signer=%s source=%s reason=%s",
			r.Artifact.AssetName, r.Result.State, r.Result.SignerWorkflow, r.Result.SourceRepoURI, r.Result.Reason)
	}
	for _, f := range findings {
		t.Logf("finding %s: %s", f.RuleID, f.Description)
	}
}

// GitHub serves bundles snappy-compressed. Reading them raw yields bytes that
// are not JSON, which would report every correctly attested release as
// unverifiable — the worst possible false positive for this feature.
func TestDecodeBundleBody(t *testing.T) {
	plain := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)

	for _, tc := range []struct {
		name        string
		contentType string
		body        []byte
		want        []byte
		wantErr     bool
	}{
		{name: "plain json passes through", contentType: "application/json", body: plain, want: plain},
		{name: "snappy by content type", contentType: "application/x-snappy", body: snappy.Encode(nil, plain), want: plain},
		{
			// GitHub's storage format is an implementation detail that has
			// changed before, so shape wins when the header is unhelpful.
			name:        "snappy inferred when body is not json",
			contentType: "application/octet-stream",
			body:        snappy.Encode(nil, plain),
			want:        plain,
		},
		{name: "leading whitespace still reads as json", contentType: "", body: append([]byte("\n  "), plain...), want: append([]byte("\n  "), plain...)},
		{name: "garbage is an error", contentType: "application/x-snappy", body: []byte{0xff, 0xfe, 0xfd}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeBundleBody(tc.contentType, tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeBundleBody: %v", err)
			}
			if string(got) != string(tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSameHost(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://api.github.com/x", "https://api.github.com", true},
		{"https://API.GitHub.com/x", "https://api.github.com", true},
		{"https://tmaproduction.blob.core.windows.net/x", "https://api.github.com", false},
		{"://bad", "https://api.github.com", false},
		// The classic bypass: userinfo that reads like the trusted host. The
		// real host is evil.com, and the token must not follow.
		{"https://api.github.com@evil.com/x", "https://api.github.com", false},
		{"https://api.github.com.evil.com/x", "https://api.github.com", false},
		{"https://api.github.com:8443/x", "https://api.github.com", false},
	} {
		if got := sameHost(tc.a, tc.b); got != tc.want {
			t.Errorf("sameHost(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
