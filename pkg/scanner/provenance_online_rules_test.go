package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeVerifier is an in-memory ProvenanceVerifier for testing the audit with no
// network.
type fakeVerifier struct {
	// artifacts is what LatestReleaseArtifacts returns.
	artifacts []ReleaseArtifact
	// listErr, when set, is returned instead of artifacts.
	listErr error
	// results maps asset name → verdict. A missing key means Verify errors.
	results map[string]ProvenanceResult
	// verifyCalls counts Verify invocations, so the cap can be asserted.
	verifyCalls int
}

func (f *fakeVerifier) LatestReleaseArtifacts(_ context.Context, _, _ string) ([]ReleaseArtifact, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.artifacts, nil
}

func (f *fakeVerifier) Verify(_ context.Context, a ReleaseArtifact) (ProvenanceResult, error) {
	f.verifyCalls++
	res, ok := f.results[a.AssetName]
	if !ok {
		return ProvenanceResult{}, errors.New("lookup failed")
	}
	return res, nil
}

func asset(name string) ReleaseArtifact {
	return ReleaseArtifact{
		Owner:      "acme",
		Repo:       "widget",
		ReleaseTag: "v1.4.0",
		AssetName:  name,
		Digest:     "sha256:" + name,
	}
}

func auditProvenance(v ProvenanceVerifier) ([]Finding, []ProvenanceRecord) {
	return AuditReleaseProvenance(context.Background(), "acme", "widget", v)
}

func TestAuditReleaseProvenanceNoReleaseIsSilent(t *testing.T) {
	// The load-bearing guard: a repo that publishes no releases says nothing
	// about its build integrity, so it must not lose a SLSA level over it.
	findings, records := auditProvenance(&fakeVerifier{})
	if len(findings) != 0 {
		t.Errorf("want no findings for a repo with no releases, got %d: %+v", len(findings), findings)
	}
	if len(records) != 0 {
		t.Errorf("want no records, got %d", len(records))
	}
}

func TestAuditReleaseProvenanceListErrorIsSilent(t *testing.T) {
	findings, _ := auditProvenance(&fakeVerifier{listErr: errors.New("503")})
	if len(findings) != 0 {
		t.Errorf("a transport failure must not produce findings, got %+v", findings)
	}
}

func TestAuditReleaseProvenanceMissingAttestation(t *testing.T) {
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("widget-linux-amd64")},
		results: map[string]ProvenanceResult{
			"widget-linux-amd64": {State: ProvenanceMissing},
		},
	}
	findings, records := auditProvenance(v)
	if !hasRule(findings, RuleSLSAAttestationMissing) {
		t.Fatalf("want %s, got %+v", RuleSLSAAttestationMissing, findings)
	}
	if len(records) != 1 || records[0].Result.State != ProvenanceMissing {
		t.Errorf("want one missing record, got %+v", records)
	}
}

func TestAuditReleaseProvenanceUnverifiable(t *testing.T) {
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("widget.tar.gz")},
		results: map[string]ProvenanceResult{
			"widget.tar.gz": {
				State:          ProvenanceUnverifiable,
				Reason:         "transparency log inclusion proof failed",
				SignerWorkflow: "https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1.4.0",
			},
		},
	}
	findings, records := auditProvenance(v)
	if !hasRule(findings, RuleSLSAAttestationUnverifiable) {
		t.Fatalf("want %s, got %+v", RuleSLSAAttestationUnverifiable, findings)
	}
	// The reason and the signer belong in the text — Finding has nowhere else
	// to put them.
	// The reason and the signer belong in the EVIDENCE, not the description:
	// a description naming them would embed per-release values and mint a new
	// fingerprint every release. See TestProvenanceFingerprintsSurviveARelease.
	if len(records) != 1 || records[0].Result.Reason == "" || records[0].Result.SignerWorkflow == "" {
		t.Errorf("evidence must carry the reason and signer, got %+v", records)
	}
}

func TestAuditReleaseProvenanceVerifiedIsSilent(t *testing.T) {
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("widget.tar.gz")},
		results: map[string]ProvenanceResult{
			"widget.tar.gz": {
				State:          ProvenanceVerified,
				SourceRepoURI:  "https://github.com/acme/widget",
				SignerWorkflow: "https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1.4.0",
			},
		},
	}
	findings, records := auditProvenance(v)
	if len(findings) != 0 {
		t.Errorf("a verified artifact from the expected repo must produce no finding, got %+v", findings)
	}
	if len(records) != 1 || records[0].Result.State != ProvenanceVerified {
		t.Errorf("evidence must still be recorded for a clean verify, got %+v", records)
	}
}

func TestAuditReleaseProvenanceUnexpectedIdentity(t *testing.T) {
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("widget.tar.gz")},
		results: map[string]ProvenanceResult{
			"widget.tar.gz": {
				State:          ProvenanceVerified,
				SourceRepoURI:  "https://github.com/attacker/widget",
				SignerWorkflow: "https://github.com/attacker/widget/.github/workflows/release.yml@refs/heads/main",
			},
		},
	}
	findings, records := auditProvenance(v)
	if !hasRule(findings, RuleSLSAAttestationIdentity) {
		t.Fatalf("want %s, got %+v", RuleSLSAAttestationIdentity, findings)
	}
	if !strings.Contains(findings[0].Description, "https://github.com/attacker/widget") {
		t.Errorf("description should name the unexpected source, got %q", findings[0].Description)
	}
	// The state, not just the finding, has to carry it. Everything downstream
	// stores and renders the state; leaving it "verified" would show the one
	// case this pass exists to catch as a pass.
	if len(records) != 1 || records[0].Result.State != ProvenanceForeignSigner {
		t.Fatalf("want the record downgraded to %q, got %+v", ProvenanceForeignSigner, records)
	}
}

// A certificate with no Source Repository URI cannot be credited to this
// repository. Treating a missing extension as a pass is fail-open on the one
// field that decides whether the signature means anything.
func TestAuditReleaseProvenanceAbsentSourceIsNotVerified(t *testing.T) {
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("widget.tar.gz")},
		results: map[string]ProvenanceResult{
			"widget.tar.gz": {State: ProvenanceVerified, SourceRepoURI: ""},
		},
	}
	findings, records := auditProvenance(v)
	if !hasRule(findings, RuleSLSAAttestationIdentity) {
		t.Fatalf("want %s, got %+v", RuleSLSAAttestationIdentity, findings)
	}
	if records[0].Result.State != ProvenanceForeignSigner {
		t.Errorf("state = %q, want %q", records[0].Result.State, ProvenanceForeignSigner)
	}
	if !strings.Contains(findings[0].Description, "no source repository") {
		t.Errorf("description should say the certificate names none, got %q", findings[0].Description)
	}
}

func TestAuditReleaseProvenanceIdentityCaseInsensitive(t *testing.T) {
	// GitHub owner/repo names are case-insensitive; a case difference is not a
	// compromise.
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("widget.tar.gz")},
		results: map[string]ProvenanceResult{
			"widget.tar.gz": {State: ProvenanceVerified, SourceRepoURI: "https://github.com/ACME/Widget"},
		},
	}
	findings, records := auditProvenance(v)
	if len(findings) != 0 {
		t.Errorf("case-only difference must not fire, got %+v", findings)
	}
	if records[0].Result.State != ProvenanceVerified {
		t.Errorf("state = %q, want %q", records[0].Result.State, ProvenanceVerified)
	}
}

func TestAuditReleaseProvenancePerArtifactErrorIsSwallowed(t *testing.T) {
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("good"), asset("broken")},
		results: map[string]ProvenanceResult{
			"good": {State: ProvenanceMissing},
			// "broken" is absent, so Verify errors.
		},
	}
	findings, records := auditProvenance(v)
	if len(findings) != 1 || findings[0].RuleID != RuleSLSAAttestationMissing {
		t.Errorf("a per-artifact error must not sink the pass, got %+v", findings)
	}
	if len(records) != 1 {
		t.Errorf("an errored artifact must not be recorded as evidence, got %+v", records)
	}
}

// One finding per rule, not per asset. A release with twenty binaries used to
// yield twenty identical HIGH rows, which both swamps the triage queue and
// distorts the severity rollup a repository is judged by.
func TestAuditReleaseProvenanceCollapsesPerRule(t *testing.T) {
	arts := []ReleaseArtifact{}
	results := map[string]ProvenanceResult{}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("asset-%d", i)
		arts = append(arts, asset(name))
		results[name] = ProvenanceResult{State: ProvenanceMissing}
	}
	// One asset fails a different way, so a second rule is genuinely due.
	results["asset-0"] = ProvenanceResult{State: ProvenanceUnverifiable, Reason: "bad signature"}

	findings, records := auditProvenance(&fakeVerifier{artifacts: arts, results: results})
	if len(findings) != 2 {
		t.Fatalf("want one finding per rule (2), got %d: %+v", len(findings), findings)
	}
	if !hasRule(findings, RuleSLSAAttestationMissing) || !hasRule(findings, RuleSLSAAttestationUnverifiable) {
		t.Errorf("both rules should fire once, got %+v", findings)
	}
	// Every asset is still accounted for in the evidence.
	if len(records) != 8 {
		t.Errorf("want 8 evidence rows, got %d", len(records))
	}
}

// Fingerprints hash the description (fingerprint.go). A description naming the
// release tag, the asset or its digest therefore mints a brand-new identity on
// every release: triage decisions would never carry over, and the alerts feed
// would re-announce an unchanged condition forever.
func TestProvenanceFingerprintsSurviveARelease(t *testing.T) {
	release := func(tag, digest string) []Finding {
		name := "widget-" + tag + ".tar.gz"
		v := &fakeVerifier{
			artifacts: []ReleaseArtifact{{
				Owner: "acme", Repo: "widget", ReleaseTag: tag, AssetName: name, Digest: digest,
			}},
			results: map[string]ProvenanceResult{name: {State: ProvenanceMissing}},
		}
		f, _ := AuditReleaseProvenance(context.Background(), "acme", "widget", v)
		AssignFingerprints(f)
		return f
	}

	first := release("v1.0.0", "sha256:aaa")
	second := release("v1.1.0", "sha256:bbb")
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("want one finding per release, got %d and %d", len(first), len(second))
	}
	if first[0].Fingerprint != second[0].Fingerprint {
		t.Errorf("fingerprint changed across releases (%s vs %s) — triage would not persist",
			first[0].Fingerprint, second[0].Fingerprint)
	}
}

func TestAuditReleaseProvenanceSkipsUndigestedAssets(t *testing.T) {
	a := asset("legacy.zip")
	a.Digest = ""
	v := &fakeVerifier{artifacts: []ReleaseArtifact{a}}
	findings, records := auditProvenance(v)
	if len(findings) != 0 || len(records) != 0 {
		t.Errorf("an asset with no digest cannot be looked up; want silence, got %+v / %+v", findings, records)
	}
	if v.verifyCalls != 0 {
		t.Errorf("want no Verify call for an undigested asset, got %d", v.verifyCalls)
	}
}

func TestAuditReleaseProvenanceCapsArtifacts(t *testing.T) {
	var arts []ReleaseArtifact
	results := map[string]ProvenanceResult{}
	for i := 0; i < MaxProvenanceArtifacts+15; i++ {
		name := fmt.Sprintf("asset-%d", i)
		arts = append(arts, asset(name))
		results[name] = ProvenanceResult{State: ProvenanceVerified, SourceRepoURI: "https://github.com/acme/widget"}
	}
	v := &fakeVerifier{artifacts: arts, results: results}
	_, records := auditProvenance(v)
	if v.verifyCalls != MaxProvenanceArtifacts {
		t.Errorf("want %d Verify calls, got %d", MaxProvenanceArtifacts, v.verifyCalls)
	}
	if len(records) != MaxProvenanceArtifacts {
		t.Errorf("want %d records, got %d", MaxProvenanceArtifacts, len(records))
	}
}

func TestAuditReleaseProvenanceStampsConfidence(t *testing.T) {
	v := &fakeVerifier{
		artifacts: []ReleaseArtifact{asset("widget.tar.gz")},
		results:   map[string]ProvenanceResult{"widget.tar.gz": {State: ProvenanceMissing}},
	}
	findings, _ := auditProvenance(v)
	if len(findings) != 1 || findings[0].Confidence == "" {
		t.Errorf("findings must carry a stamped confidence, got %+v", findings)
	}
	if findings[0].File != SettingsFile {
		t.Errorf("release findings are not workflow-line findings; want %q, got %q", SettingsFile, findings[0].File)
	}
}

// The catalog must know the rules, or they can't be toggled, documented, or
// filtered into the SLSA rulesets that drive the dashboard.
func TestProvenanceRulesAreInCatalog(t *testing.T) {
	want := map[RuleID]string{
		RuleSLSAAttestationMissing:      FrameworkSLSABuildL2,
		RuleSLSAAttestationUnverifiable: FrameworkSLSABuildL2,
		RuleSLSAAttestationIdentity:     FrameworkSLSABuildL3,
	}
	got := map[RuleID]RuleSpec{}
	for _, spec := range Rules() {
		if _, ok := want[spec.ID]; ok {
			got[spec.ID] = spec
		}
	}
	for id, framework := range want {
		spec, ok := got[id]
		if !ok {
			t.Errorf("%s is missing from the rule catalog", id)
			continue
		}
		if spec.DocURL != "/rules/"+string(id) {
			t.Errorf("%s: doc_url = %q, want /rules/%s", id, spec.DocURL, id)
		}
		if len(spec.Frameworks) != 1 || spec.Frameworks[0] != framework {
			t.Errorf("%s: frameworks = %v, want [%s]", id, spec.Frameworks, framework)
		}
		if spec.Surface != SurfaceRepoSettings {
			t.Errorf("%s: surface = %q, want %q", id, spec.Surface, SurfaceRepoSettings)
		}
	}
}

// FilterFindings drives the /slsa dashboard's per-level views, so each rule has
// to survive the ruleset it claims.
func TestProvenanceRulesSurviveSLSARulesets(t *testing.T) {
	findings := []Finding{
		{RuleID: RuleSLSAAttestationMissing, Category: "SLSA-BUILD-L2"},
		{RuleID: RuleSLSAAttestationUnverifiable, Category: "SLSA-BUILD-L2"},
		{RuleID: RuleSLSAAttestationIdentity, Category: "SLSA-BUILD-L3"},
	}
	for _, tc := range []struct {
		ruleset string
		want    int
	}{
		{"slsa", 3},
		{"slsa-build-l2", 2},
		{"slsa-build-l3", 1},
	} {
		if got := len(FilterFindings(findings, tc.ruleset)); got != tc.want {
			t.Errorf("ruleset %q: kept %d findings, want %d", tc.ruleset, got, tc.want)
		}
	}
}
