package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// CICD-SEC-7 — a build artifact left downloadable for the full default window.
//
// An uploaded artifact is a zip anyone with read access to the repository can
// download, for as long as it is retained. On a public repository that is
// everyone. The default retention is 90 days, and an organisation can raise it
// to 400 — so "we didn't set it" and "we set it to the maximum" produce the
// same file sitting there for over a year.
//
// Most artifacts are a compiled binary nobody cares about, which is why this
// does not fire on every upload. It fires where the artifact is likely to carry
// something: the workflow handles secrets or publishes a release (so the build
// tree may hold a token, a signing key, or a .env the build wrote), or the
// uploaded path itself names a credential.
//
// Repository visibility is the other half of the risk and is NOT visible here:
// a workflow file does not say whether its repository is public. The rule
// therefore gates on what the file does show, and the docs say plainly that a
// public repository makes every one of these findings worse rather than
// pretending the scanner knows which.

// uploadArtifactAction is the action this rule inspects. download-artifact is
// deliberately absent: consuming an artifact is not publishing one.
const uploadArtifactAction = "actions/upload-artifact"

// maxRetentionDays is the ceiling this rule accepts. It matches GitHub's own
// default, so the rule is not arguing for a shorter window than GitHub ships —
// it is arguing against inheriting an organisation default that may be far
// longer, and against leaving the decision unmade.
const maxRetentionDays = 90

// credentialPathRe matches an artifact path that names a credential outright.
// Such a path is sensitive whatever the rest of the workflow does.
var credentialPathRe = regexp.MustCompile(`(?i)(^|[/\\.\s])(\.env(\.|$|/)|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|credentials?(\.json|\.yml|\.yaml)?$|.*\.(pem|p12|pfx|jks|keystore|key)$)`)

// CheckArtifactExposure flags upload-artifact steps that publish potentially
// sensitive output without a retention cap.
func CheckArtifactExposure(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []Finding {
	var findings []Finding

	for _, jobWrap := range jobs {
		j := jobWrap
		// prTarget is not a sensitivity signal for this rule — the question is
		// what the artifact might contain, not who triggered the run.
		jobReason, jobSensitive := sensitiveJobTrait(j, false)

		for _, step := range decodeSteps(j.Node) {
			s := step
			if s.Uses.Value == "" || actionRepo(s.Uses.Value) != uploadArtifactAction {
				continue
			}

			path := artifactPath(&s.With)
			pathSensitive := path != "" && credentialPathRe.MatchString(path)
			if !jobSensitive && !pathSensitive {
				continue
			}

			_, why, capped := retentionState(&s.With)
			if capped {
				continue
			}

			reason := jobReason
			if pathSensitive {
				reason = fmt.Sprintf("uploads %q, a path that names a credential", path)
			}

			findings = append(findings, Finding{
				File:     file,
				Line:     s.Uses.Line,
				Column:   s.Uses.Column,
				Severity: SeverityMedium,
				Category: "CICD-SEC-7",
				RuleID:   RuleArtifactExposure,
				Title:    "Build artifact published without a retention cap",
				Description: fmt.Sprintf(
					"Step %q in job %q uploads an artifact and %s, but %s. "+
						"An uploaded artifact is a zip that anyone with read access to the repository can download for the whole retention window — everyone, on a public repository. "+
						"GitHub's default is %d days and an organisation may set it as high as 400.",
					stepName(&s), j.ID, reason, why, maxRetentionDays,
				),
				Recommendation: fmt.Sprintf("Set `retention-days:` on the upload step to the shortest window that is actually useful — often 1–7 days for a build artifact a later job consumes. `%d` is a ceiling, not a recommendation. If the artifact may contain a token, a signing key, or a .env the build wrote, do not upload it at all.", maxRetentionDays),
				Confidence:     ConfidenceMedium,
			})
		}
	}
	return findings
}

// artifactPath returns the step's `path:` input, or empty when absent. Only
// the first line matters for the credential-name test; a multi-path upload is
// matched line by line.
func artifactPath(with *yaml.Node) string {
	v := mappingValueByKey(with, "path")
	if v == nil {
		return ""
	}
	return strings.TrimSpace(v.Value)
}

// retentionState reports the step's retention setting: the value, a phrase
// naming the problem, and whether the setting is acceptable.
//
// A templated value (`${{ inputs.retention }}`) counts as acceptable. The
// scanner cannot evaluate it, and guessing would either flag a workflow that
// is already parameterised correctly or hand the fixer a value to overwrite.
func retentionState(with *yaml.Node) (value string, why string, capped bool) {
	v := mappingValueByKey(with, "retention-days")
	if v == nil {
		return "", "sets no retention-days, so the artifact is kept for the repository's default window", false
	}
	raw := strings.TrimSpace(v.Value)
	if strings.Contains(raw, "${{") {
		return raw, "", true
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		// Unparseable and not an expression — leave it alone rather than
		// rewrite something we do not understand.
		return raw, "", true
	}
	if n <= maxRetentionDays {
		return raw, "", true
	}
	return raw, fmt.Sprintf("keeps it for %s days", raw), false
}

// --- Auto-fix (partial) -----------------------------------------------------

// artifactRetentionFixMarker tags the comment this fixer writes, so a second
// pass recognises its own work.
const artifactRetentionFixMarker = "pipefort: artifact retention"

// fixArtifactExposure adds a retention cap to an upload-artifact step,
// creating the `with:` block if the step has none.
//
// Partial, and comment-guarded. maxRetentionDays is a ceiling that stops the
// artifact inheriting a 400-day organisation default; it is not the right
// answer for a build artifact a later job consumes ten minutes later, and it is
// not an answer at all for an artifact that should never have been uploaded.
// The comment says so on the line the author will read.
func fixArtifactExposure(rootNode *yaml.Node, f Finding) bool {
	usesNode := findNodeByPosition(rootNode, f.Line, f.Column)
	if usesNode == nil || usesNode.Kind != yaml.ScalarNode {
		return false
	}
	stepNode := findParentMappingNode(rootNode, usesNode)
	if stepNode == nil || mapKeyForValue(stepNode, usesNode) != "uses" {
		return false
	}

	_, with, _ := findMapKey(stepNode, "with")
	if with == nil {
		with = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMapKey(stepNode, "with", with)
	}
	if with.Kind != yaml.MappingNode {
		return false
	}
	if _, existing, _ := findMapKey(with, "retention-days"); existing != nil {
		return false
	}

	key := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: "retention-days",
		HeadComment: fmt.Sprintf("%s — %d days is a ceiling, not a recommendation. Shorten it to the window this artifact is actually useful for, or stop uploading it if it may contain a credential.",
			artifactRetentionFixMarker, maxRetentionDays),
	}
	val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(maxRetentionDays)}
	with.Content = append(with.Content, key, val)
	return true
}
