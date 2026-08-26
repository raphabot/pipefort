package scanner

import (
	"context"
	"fmt"
	"strings"
)

// Online verification of *released artifacts* against their SLSA build
// provenance attestations. The offline slsa_rules.go checks only ask whether a
// workflow YAML *declares* provenance; nothing there confirms that a release
// actually carries a signed attestation, nor who signed it.
//
// That gap is the shape of six CNCF-catalogued compromises — SUNBURST/SUNSPOT,
// Octopus Scanner, Webmin, the ROS build farm, ShadowHammer and CCleaner — in
// which a compromised builder emitted a correctly signed artifact. A signature
// check cannot separate those from a legitimate release. Verifying the
// attestation can, because it binds the artifact to the workflow identity that
// produced it.
//
// Like AuditActionPins, this pass needs the network and a token, so it never
// runs inline in ScanBytes, which must stay pure for the serverless per-repo
// web scans.
//
// Three audits:
//   - attestation-missing      — a release asset has no attestation at all
//   - attestation-unverifiable — an attestation exists but fails verification
//   - attestation-identity     — it verifies, but a foreign workflow signed it

// MaxProvenanceArtifacts bounds the per-repo call count the way AuditActionPins
// bounds its lookups: a release with hundreds of assets must not turn one scan
// into hundreds of round-trips.
const MaxProvenanceArtifacts = 20

// ReleaseArtifact is one published file we can ask about. Digest comes straight
// from the GitHub release asset's `digest` field, so nothing is downloaded.
type ReleaseArtifact struct {
	Owner      string
	Repo       string
	ReleaseTag string // e.g. "v1.4.0"
	AssetName  string
	Digest     string // "sha256:<hex>"
}

// ProvenanceState is the verdict for a single artifact.
type ProvenanceState string

const (
	// ProvenanceMissing means no attestation exists for the artifact's digest.
	ProvenanceMissing ProvenanceState = "missing"
	// ProvenanceUnverifiable means an attestation exists but failed
	// cryptographic verification (signature, certificate chain, transparency
	// log inclusion, or subject-digest mismatch).
	ProvenanceUnverifiable ProvenanceState = "unverifiable"
	// ProvenanceVerified means the attestation verified end to end.
	ProvenanceVerified ProvenanceState = "verified"
)

// ProvenanceResult is what a verifier reports for one artifact. The identity
// fields are read from the Fulcio certificate's extensions and are the point of
// the whole exercise: "signed" is not the same as "signed by the builder you
// expect".
type ProvenanceResult struct {
	State ProvenanceState
	// SignerWorkflow is the Build Signer URI (OID 1.3.6.1.4.1.57264.1.9) — the
	// specific workflow ref that requested the signing certificate.
	SignerWorkflow string
	// SourceRepoURI is the Source Repository URI (OID 1.3.6.1.4.1.57264.1.12).
	SourceRepoURI string
	// Issuer is the OIDC issuer (OID 1.3.6.1.4.1.57264.1.8).
	Issuer string
	// PredicateType is the in-toto predicate the attestation carries.
	PredicateType string
	// Reason explains a non-verified state, for the finding text.
	Reason string
}

// ProvenanceRecord pairs an artifact with its verdict. Finding carries no
// free-form metadata, so consumers that want the structured evidence (the SaaS
// dashboard) read these instead of parsing finding text.
type ProvenanceRecord struct {
	Artifact ReleaseArtifact
	Result   ProvenanceResult
}

// ProvenanceVerifier performs the network lookups and cryptographic
// verification the audit needs. It is an interface, mirroring PinAuditor, so
// the rules can be unit-tested with a fake and no network.
type ProvenanceVerifier interface {
	// LatestReleaseArtifacts returns the assets of owner/repo's latest release.
	// An empty slice (no releases, or a release with no assets) means there is
	// nothing to verify — not a failure.
	LatestReleaseArtifacts(ctx context.Context, owner, repo string) ([]ReleaseArtifact, error)
	// Verify checks one artifact's attestation and reports the verdict.
	Verify(ctx context.Context, a ReleaseArtifact) (ProvenanceResult, error)
}

// AuditReleaseProvenance verifies the latest release's assets and returns both
// the findings and the structured evidence behind them.
//
// A repository that publishes no releases produces no findings. That guard is
// load-bearing: without it every repo that simply doesn't ship release assets
// would fire an L2 rule and lose its Build level, which would say nothing about
// its build integrity.
//
// Lookup errors are swallowed per-artifact, matching AuditActionPins — a
// transient failure yields no finding rather than a false positive.
func AuditReleaseProvenance(ctx context.Context, owner, repo string, v ProvenanceVerifier) ([]Finding, []ProvenanceRecord) {
	artifacts, err := v.LatestReleaseArtifacts(ctx, owner, repo)
	if err != nil || len(artifacts) == 0 {
		return nil, nil
	}
	if len(artifacts) > MaxProvenanceArtifacts {
		artifacts = artifacts[:MaxProvenanceArtifacts]
	}

	expectedSource := "https://github.com/" + owner + "/" + repo

	var findings []Finding
	records := make([]ProvenanceRecord, 0, len(artifacts))

	for _, a := range artifacts {
		// An asset GitHub has not digested cannot be looked up by subject.
		if a.Digest == "" {
			continue
		}
		res, err := v.Verify(ctx, a)
		if err != nil {
			continue
		}
		records = append(records, ProvenanceRecord{Artifact: a, Result: res})

		switch res.State {
		case ProvenanceMissing:
			findings = append(findings, attestationMissingFinding(a))
		case ProvenanceUnverifiable:
			findings = append(findings, attestationUnverifiableFinding(a, res))
		case ProvenanceVerified:
			// Verified, but by whom? A certificate naming a source repository
			// other than this one is the SolarWinds shape: a real signature
			// from a builder that has no business producing this artifact.
			if res.SourceRepoURI != "" && !strings.EqualFold(res.SourceRepoURI, expectedSource) {
				findings = append(findings, attestationIdentityFinding(a, res, expectedSource))
			}
		}
	}

	return StampConfidence(findings), records
}

// signerSuffix renders the signing identity for finding text, when known.
func signerSuffix(res ProvenanceResult) string {
	if res.SignerWorkflow == "" {
		return ""
	}
	return fmt.Sprintf(" The signing certificate names %s.", res.SignerWorkflow)
}

func attestationMissingFinding(a ReleaseArtifact) Finding {
	return Finding{
		File:     SettingsFile,
		Severity: SeverityHigh,
		Category: "SLSA-BUILD-L2",
		RuleID:   RuleSLSAAttestationMissing,
		Title:    "Release asset has no build provenance attestation",
		Description: fmt.Sprintf(
			"Release %s publishes %q (%s), but GitHub holds no attestation for that digest. "+
				"Consumers have no way to tell whether the file was produced by your build or substituted afterwards — "+
				"exactly the gap SolarWinds, CCleaner and ShadowHammer exploited.",
			a.ReleaseTag, a.AssetName, a.Digest),
		Recommendation: "Generate provenance in the release workflow with actions/attest-build-provenance (or the slsa-github-generator reusable workflow) so every published asset carries a signed, verifiable attestation.",
	}
}

func attestationUnverifiableFinding(a ReleaseArtifact, res ProvenanceResult) Finding {
	reason := res.Reason
	if reason == "" {
		reason = "verification failed"
	}
	return Finding{
		File:     SettingsFile,
		Severity: SeverityHigh,
		Category: "SLSA-BUILD-L2",
		RuleID:   RuleSLSAAttestationUnverifiable,
		Title:    "Build provenance attestation does not verify",
		Description: fmt.Sprintf(
			"Release %s publishes %q (%s) with an attestation that fails verification: %s.%s "+
				"An attestation that cannot be verified provides no assurance at all — it is weaker than none, because it looks like coverage.",
			a.ReleaseTag, a.AssetName, a.Digest, reason, signerSuffix(res)),
		Recommendation: "Re-run the release with a working attestation step and confirm locally with `gh attestation verify <file> --repo <owner>/<repo>`. If verification fails against a release you did publish, treat the signing path as compromised until proven otherwise.",
	}
}

func attestationIdentityFinding(a ReleaseArtifact, res ProvenanceResult, expectedSource string) Finding {
	return Finding{
		File:     SettingsFile,
		Severity: SeverityMedium,
		Category: "SLSA-BUILD-L3",
		RuleID:   RuleSLSAAttestationIdentity,
		Title:    "Build provenance is signed by an unexpected workflow identity",
		Description: fmt.Sprintf(
			"Release %s publishes %q with a valid attestation, but the certificate names source repository %s rather than %s.%s "+
				"A correctly signed artifact from the wrong builder is the signature every build-infrastructure compromise leaves behind.",
			a.ReleaseTag, a.AssetName, res.SourceRepoURI, expectedSource, signerSuffix(res)),
		Recommendation: "Confirm the release was built by this repository's own workflow. If the identity is a deliberate part of your release path (a shared builder repo, say), document it; otherwise treat the artifact as untrusted and rotate the signing path.",
	}
}
