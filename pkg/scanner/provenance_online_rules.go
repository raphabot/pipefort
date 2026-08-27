package scanner

import (
	"context"
	"fmt"
	"sort"
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
	// ProvenanceVerified means the attestation verified end to end AND names
	// this repository as its source.
	ProvenanceVerified ProvenanceState = "verified"
	// ProvenanceSkipped means the artifact could not be checked at all — no
	// digest to look it up by, or the lookup failed. Recorded rather than
	// dropped: an artifact missing from the evidence is indistinguishable from
	// one that passed, and "we did not look" must never read as "it is fine".
	ProvenanceSkipped ProvenanceState = "skipped"
	// ProvenanceForeignSigner means the attestation is cryptographically sound
	// but was signed for a different source repository — or names none at all.
	//
	// This is a distinct state rather than a flavour of "verified" because
	// every consumer downstream reads the state and nothing else. Reporting a
	// foreign signer as verified would render the one case this whole pass
	// exists to catch as a pass.
	ProvenanceForeignSigner ProvenanceState = "identity-mismatch"
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
func AuditReleaseProvenance(ctx context.Context, owner, repo string, v ProvenanceVerifier) ([]Finding, []ProvenanceRecord, error) {
	artifacts, err := v.LatestReleaseArtifacts(ctx, owner, repo)
	if err != nil {
		// Returned, not swallowed. The common cause is a missing
		// `attestations: read` permission, and reporting that as "this release
		// has no attestations" would be a false accusation dressed as a
		// finding.
		return nil, nil, err
	}
	if len(artifacts) == 0 {
		return nil, nil, nil
	}
	// Truncation is recorded, not silent: a 50-asset release must not report
	// "every published asset verifies" on the strength of the first twenty.
	var truncated []ReleaseArtifact
	if len(artifacts) > MaxProvenanceArtifacts {
		truncated = artifacts[MaxProvenanceArtifacts:]
		artifacts = artifacts[:MaxProvenanceArtifacts]
	}

	expectedSource := "https://github.com/" + owner + "/" + repo

	records := make([]ProvenanceRecord, 0, len(artifacts)+len(truncated))

	for _, a := range truncated {
		records = append(records, ProvenanceRecord{
			Artifact: a,
			Result:   ProvenanceResult{State: ProvenanceSkipped, Reason: "not checked: per-release asset cap reached"},
		})
	}

	for _, a := range artifacts {
		// GitHub has only published digests for assets uploaded since June
		// 2025; an older one cannot be looked up by subject at all.
		if a.Digest == "" {
			records = append(records, ProvenanceRecord{
				Artifact: a,
				Result:   ProvenanceResult{State: ProvenanceSkipped, Reason: "GitHub publishes no digest for this asset"},
			})
			continue
		}
		res, err := v.Verify(ctx, a)
		if err != nil {
			records = append(records, ProvenanceRecord{
				Artifact: a,
				Result:   ProvenanceResult{State: ProvenanceSkipped, Reason: err.Error()},
			})
			continue
		}

		// Verified, but by whom? A certificate naming a source repository
		// other than this one is the SolarWinds shape: a real signature from a
		// builder that has no business producing this artifact. The verdict is
		// downgraded rather than merely annotated, because the state is what
		// every consumer stores, rolls up and renders.
		if res.State == ProvenanceVerified && !signedBySource(res, expectedSource) {
			res.State = ProvenanceForeignSigner
		}

		records = append(records, ProvenanceRecord{Artifact: a, Result: res})
	}

	return StampConfidence(provenanceFindings(records, expectedSource)), records, nil
}

// provenanceFindings reduces per-asset evidence to at most one finding per rule.
//
// One finding per ASSET would be both noisy — a release with twenty binaries
// yields twenty identical HIGH rows, distorting the severity rollup — and,
// worse, unstable: fingerprints hash the description, so naming the release tag
// and digest would mint brand-new fingerprints on every release. Triage
// decisions would never carry over and the alerts feed would re-announce an
// unchanged condition forever.
//
// So the descriptions here are deliberately free of release tags, digests,
// asset names and counts. The per-asset detail lives in the returned records,
// which is what the evidence table stores and the CLI prints.
func provenanceFindings(records []ProvenanceRecord, expectedSource string) []Finding {
	var missing, unverifiable bool
	foreignSources := map[string]bool{}
	for _, r := range records {
		switch r.Result.State {
		case ProvenanceMissing:
			missing = true
		case ProvenanceUnverifiable:
			unverifiable = true
		case ProvenanceForeignSigner:
			named := r.Result.SourceRepoURI
			if named == "" {
				named = "no source repository at all"
			}
			foreignSources[named] = true
		}
	}

	var findings []Finding
	if missing {
		findings = append(findings, attestationMissingFinding())
	}
	if unverifiable {
		findings = append(findings, attestationUnverifiableFinding())
	}
	if len(foreignSources) > 0 {
		named := make([]string, 0, len(foreignSources))
		for k := range foreignSources {
			named = append(named, k)
		}
		sort.Strings(named)
		findings = append(findings, attestationIdentityFinding(named, expectedSource))
	}
	return findings
}

// signedBySource reports whether a verified attestation names the repository
// being scanned as its source.
//
// A certificate carrying NO Source Repository URI fails this too. Reading a
// missing extension as a pass would be fail-open on precisely the field that
// decides whether a signature means anything, and the identity policy only
// admits GitHub Actions certificates, which always carry it.
func signedBySource(res ProvenanceResult, expectedSource string) bool {
	return res.SourceRepoURI != "" && strings.EqualFold(res.SourceRepoURI, expectedSource)
}

func attestationMissingFinding() Finding {
	return Finding{
		File:     SettingsFile,
		Severity: SeverityHigh,
		Category: "SLSA-BUILD-L2",
		RuleID:   RuleSLSAAttestationMissing,
		Title:    "Release assets have no build provenance attestation",
		Description: "This repository's latest release publishes assets that carry no build provenance attestation. " +
			"Consumers have no way to tell whether those files were produced by your build or substituted afterwards — " +
			"exactly the gap SolarWinds, CCleaner and ShadowHammer exploited.",
		Recommendation: "Generate provenance in the release workflow with actions/attest-build-provenance (or the slsa-github-generator reusable workflow) so every published asset carries a signed, verifiable attestation.",
	}
}

func attestationUnverifiableFinding() Finding {
	return Finding{
		File:     SettingsFile,
		Severity: SeverityHigh,
		Category: "SLSA-BUILD-L2",
		RuleID:   RuleSLSAAttestationUnverifiable,
		Title:    "Build provenance attestation does not verify",
		Description: "This repository's latest release publishes assets whose build provenance attestation fails verification. " +
			"An attestation that cannot be verified provides no assurance at all — it is weaker than none, because it looks like coverage.",
		Recommendation: "Re-run the release with a working attestation step and confirm locally with `gh attestation verify <file> --repo <owner>/<repo>`. If verification fails against a release you did publish, treat the signing path as compromised until proven otherwise.",
	}
}

func attestationIdentityFinding(namedSources []string, expectedSource string) Finding {
	return Finding{
		File:     SettingsFile,
		Severity: SeverityMedium,
		Category: "SLSA-BUILD-L3",
		RuleID:   RuleSLSAAttestationIdentity,
		Title:    "Build provenance is signed by an unexpected workflow identity",
		Description: fmt.Sprintf(
			"This repository's latest release publishes assets whose provenance is cryptographically valid but names %s rather than %s. "+
				"A correctly signed artifact from the wrong builder is the signature every build-infrastructure compromise leaves behind.",
			strings.Join(namedSources, ", "), expectedSource),
		Recommendation: "Confirm the release was built by this repository's own workflow. If the identity is a deliberate part of your release path (a shared builder repo, say), document it; otherwise treat the artifact as untrusted and rotate the signing path.",
	}
}
