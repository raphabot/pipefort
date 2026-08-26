package scanner

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/snappy"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// GitHubProvenanceVerifier is the real ProvenanceVerifier: it reads a
// repository's latest release from the GitHub API and verifies each asset's
// attestation against Sigstore.
//
// Verification is the whole point, so it is done properly — DSSE signature,
// Fulcio certificate chain, transparency-log inclusion and signed certificate
// timestamps — rather than merely observing that a bundle exists.

// githubTUFRoot is the trust anchor for GitHub's own Sigstore instance, which
// signs attestations for private repositories. See embed/README.md.
//
//go:embed embed/tuf-repo.github.com/root.json
var githubTUFRoot []byte

// githubTUFMirror is the TUF repository for GitHub's Sigstore instance.
const githubTUFMirror = "https://tuf-repo.github.com"

// provenancePredicateType is the in-toto predicate SLSA build provenance uses.
// The attestations API filters on it so we don't pull SBOMs we won't read.
const provenancePredicateType = "https://slsa.dev/provenance/v1"

// defaultGitHubAPIBase is the public GitHub API root.
const defaultGitHubAPIBase = "https://api.github.com"

// GitHubProvenanceVerifier implements ProvenanceVerifier against the GitHub
// REST API and Sigstore.
type GitHubProvenanceVerifier struct {
	// Token authenticates the API calls. The attestations endpoint needs
	// `attestations:read`; releases need `contents:read`.
	Token string
	// Client is the HTTP client for both GitHub and bundle fetches.
	Client *http.Client
	// BaseURL is the GitHub API root. It is exported and overridable so tests
	// can point it at an httptest server — deliberately unlike
	// GitHubPinAuditor, whose base URL is package-private and therefore makes
	// its online pass impossible to intercept from outside this package.
	BaseURL string
	// TrustedMaterial, when set, replaces the live Sigstore trust roots. Tests
	// set it; production leaves it nil and gets the TUF-backed roots below.
	TrustedMaterial root.TrustedMaterial

	trustOnce sync.Once
	trust     root.TrustedMaterial
	trustErr  error
}

// NewGitHubProvenanceVerifier returns a verifier using the public GitHub API.
func NewGitHubProvenanceVerifier(token string) *GitHubProvenanceVerifier {
	return &GitHubProvenanceVerifier{
		Token:   token,
		Client:  &http.Client{Timeout: 20 * time.Second},
		BaseURL: defaultGitHubAPIBase,
	}
}

var _ ProvenanceVerifier = (*GitHubProvenanceVerifier)(nil)

func (g *GitHubProvenanceVerifier) httpClient() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return http.DefaultClient
}

func (g *GitHubProvenanceVerifier) baseURL() string {
	if g.BaseURL != "" {
		return strings.TrimSuffix(g.BaseURL, "/")
	}
	return defaultGitHubAPIBase
}

// get performs an authenticated GitHub API GET, with the same headers the pin
// auditor sets.
func (g *GitHubProvenanceVerifier) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pipefort-verify-attestations")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	return g.httpClient().Do(req)
}

// releaseResponse is the slice of GET /repos/{o}/{r}/releases/latest we read.
type releaseResponse struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		// Digest is GitHub's own "sha256:<hex>" for the uploaded asset,
		// available since June 2025. It is why nothing has to be downloaded.
		Digest string `json:"digest"`
	} `json:"assets"`
}

// LatestReleaseArtifacts returns the assets of the repository's latest release.
// A repository with no releases returns an empty slice and no error — there is
// simply nothing to verify.
func (g *GitHubProvenanceVerifier) LatestReleaseArtifacts(ctx context.Context, owner, repo string) ([]ReleaseArtifact, error) {
	resp, err := g.get(ctx, fmt.Sprintf("/repos/%s/%s/releases/latest", owner, repo))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no releases published
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: releases/latest for %s/%s: %s", owner, repo, resp.Status)
	}

	var rel releaseResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rel); err != nil {
		return nil, err
	}

	artifacts := make([]ReleaseArtifact, 0, len(rel.Assets))
	for _, a := range rel.Assets {
		artifacts = append(artifacts, ReleaseArtifact{
			Owner:      owner,
			Repo:       repo,
			ReleaseTag: rel.TagName,
			AssetName:  a.Name,
			Digest:     a.Digest,
		})
	}
	return artifacts, nil
}

// attestationsResponse is GET /repos/{o}/{r}/attestations/{digest}. The bundle
// arrives inline on some responses and behind bundle_url on others, so both
// shapes are handled.
type attestationsResponse struct {
	Attestations []struct {
		Bundle    json.RawMessage `json:"bundle"`
		BundleURL string          `json:"bundle_url"`
	} `json:"attestations"`
}

// Verify checks one artifact's attestation and reports the verdict.
func (g *GitHubProvenanceVerifier) Verify(ctx context.Context, a ReleaseArtifact) (ProvenanceResult, error) {
	raw, err := g.fetchBundle(ctx, a)
	if err != nil {
		return ProvenanceResult{}, err
	}
	if raw == nil {
		return ProvenanceResult{State: ProvenanceMissing}, nil
	}

	trusted, err := g.trustedMaterial()
	if err != nil {
		// Without trust roots we cannot make any claim. Report it as a
		// transport-shaped error so the audit stays silent rather than
		// accusing a release we simply failed to check.
		return ProvenanceResult{}, err
	}

	digest, err := hex.DecodeString(strings.TrimPrefix(a.Digest, "sha256:"))
	if err != nil {
		return ProvenanceResult{
			State:  ProvenanceUnverifiable,
			Reason: fmt.Sprintf("asset digest %q is not valid hex", a.Digest),
		}, nil
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return ProvenanceResult{
			State:  ProvenanceUnverifiable,
			Reason: fmt.Sprintf("attestation bundle is malformed (%v)", err),
		}, nil
	}

	v, err := verify.NewVerifier(trusted,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return ProvenanceResult{}, err
	}

	// The identity policy is deliberately permissive — any GitHub Actions
	// OIDC identity passes. Who actually signed is then read off the verified
	// certificate and judged separately, so "cryptographically broken" and
	// "signed by someone unexpected" stay two distinct findings instead of
	// collapsing into one opaque failure.
	certID, err := verify.NewShortCertificateIdentity(
		"https://token.actions.githubusercontent.com", "", "", "^https://github.com/")
	if err != nil {
		return ProvenanceResult{}, err
	}

	res, err := v.Verify(&b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(certID),
	))
	if err != nil {
		return ProvenanceResult{
			State:  ProvenanceUnverifiable,
			Reason: err.Error(),
		}, nil
	}

	out := ProvenanceResult{State: ProvenanceVerified}
	if res.Signature != nil && res.Signature.Certificate != nil {
		cert := res.Signature.Certificate
		out.SignerWorkflow = cert.BuildSignerURI
		out.SourceRepoURI = cert.SourceRepositoryURI
		out.Issuer = cert.Issuer
		// Older certificates predate the Build Signer URI extension; the SAN
		// carries the same identity there.
		if out.SignerWorkflow == "" {
			out.SignerWorkflow = cert.SubjectAlternativeName
		}
	}
	if res.Statement != nil {
		out.PredicateType = res.Statement.PredicateType
	}
	return out, nil
}

// fetchBundle returns the raw attestation bundle JSON for an artifact, or nil
// when GitHub holds no attestation for that digest.
func (g *GitHubProvenanceVerifier) fetchBundle(ctx context.Context, a ReleaseArtifact) ([]byte, error) {
	path := fmt.Sprintf("/repos/%s/%s/attestations/%s?predicate_type=%s",
		a.Owner, a.Repo, url.PathEscape(a.Digest), url.QueryEscape(provenancePredicateType))

	resp, err := g.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: attestations for %s: %s", a.Digest, resp.Status)
	}

	var out attestationsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Attestations) == 0 {
		return nil, nil
	}

	first := out.Attestations[0]
	if len(first.Bundle) > 0 && string(first.Bundle) != "null" {
		return first.Bundle, nil
	}
	if first.BundleURL == "" {
		return nil, nil
	}
	return g.fetchBundleURL(ctx, first.BundleURL)
}

// fetchBundleURL retrieves a bundle served indirectly via bundle_url.
//
// On github.com that URL is a pre-signed blob-storage link whose credentials
// live in the query string: sending our own Authorization header alongside them
// makes the storage backend reject the request with 401. So the token travels
// only when the URL is on the same host as the API itself, which is what a
// GitHub Enterprise Server deployment serving bundles from its own domain
// needs.
func (g *GitHubProvenanceVerifier) fetchBundleURL(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pipefort-verify-attestations")
	if g.Token != "" && sameHost(rawURL, g.baseURL()) {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: bundle_url: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return decodeBundleBody(resp.Header.Get("Content-Type"), body)
}

// decodeBundleBody unwraps a bundle payload. GitHub stores bundles
// snappy-compressed (Content-Type application/x-snappy, ".json.sn" objects),
// so a raw read is not JSON. The content type is authoritative when present,
// but a payload that simply doesn't look like JSON is decompressed anyway —
// the storage format is GitHub's implementation detail and has changed before.
func decodeBundleBody(contentType string, body []byte) ([]byte, error) {
	compressed := strings.Contains(strings.ToLower(contentType), "snappy")
	if !compressed && !looksLikeJSON(body) {
		compressed = true
	}
	if !compressed {
		return body, nil
	}
	decoded, err := snappy.Decode(nil, body)
	if err != nil {
		return nil, fmt.Errorf("github: bundle_url payload is neither JSON nor snappy: %w", err)
	}
	return decoded, nil
}

// looksLikeJSON reports whether a payload begins with a JSON object, ignoring
// leading whitespace.
func looksLikeJSON(body []byte) bool {
	for _, c := range body {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// trustedMaterial resolves the Sigstore trust roots once per verifier.
//
// Both instances are trusted together: Sigstore's public-good instance signs
// attestations for public repositories, GitHub's own instance signs them for
// private ones, and a TrustedMaterialCollection accepts either — so the
// verifier never has to know which kind of repository it is looking at.
func (g *GitHubProvenanceVerifier) trustedMaterial() (root.TrustedMaterial, error) {
	if g.TrustedMaterial != nil {
		return g.TrustedMaterial, nil
	}
	g.trustOnce.Do(func() {
		var collection root.TrustedMaterialCollection

		publicGood, err := root.NewLiveTrustedRoot(tufOptions(tuf.DefaultOptions(), "sigstore"))
		if err != nil {
			g.trustErr = fmt.Errorf("sigstore public-good trust root: %w", err)
			return
		}
		collection = append(collection, publicGood)

		ghOpts := tuf.DefaultOptions()
		ghOpts.Root = githubTUFRoot
		ghOpts.RepositoryBaseURL = githubTUFMirror
		if ghRoot, err := root.NewLiveTrustedRoot(tufOptions(ghOpts, "github")); err == nil {
			collection = append(collection, ghRoot)
		}
		// A GitHub-instance failure is not fatal: public-repo attestations,
		// the overwhelming majority, still verify. Private-repo ones will
		// report as unverifiable, which is honest.

		g.trust = collection
	})
	return g.trust, g.trustErr
}

// tufOptions points the TUF cache at a writable temp directory. The default is
// under $HOME, which does not exist on serverless runtimes.
func tufOptions(opts *tuf.Options, name string) *tuf.Options {
	opts.CachePath = filepath.Join(os.TempDir(), "pipefort-tuf", name)
	opts.CacheValidity = tuf.MaxCache
	return opts
}

// sameHost reports whether two URLs share a host, so credentials meant for the
// API are never handed to a third-party storage backend.
func sameHost(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return ua.Host != "" && strings.EqualFold(ua.Host, ub.Host)
}
