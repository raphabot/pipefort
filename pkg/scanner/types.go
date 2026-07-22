package scanner

import "gopkg.in/yaml.v3"

// Severity represents the severity of a security finding.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	SeverityInfo   Severity = "INFO"
)

// Confidence expresses how certain a rule is that a finding is real (as
// opposed to how bad it would be — that's Severity). Deterministic checks
// (e.g. "no permissions block") are HIGH; pattern/heuristic checks that can
// misfire (e.g. secret-name matching, typosquat edit distance) are MEDIUM or
// LOW. Every finding gets a confidence: checks may stamp one per finding,
// and StampConfidence backfills the rule's default for the rest.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Finding represents a single security vulnerability/risk found in the pipeline.
type Finding struct {
	File           string   `json:"file"`
	Line           int      `json:"line"`
	Column         int      `json:"column"`
	Severity       Severity `json:"severity"`
	Category       string   `json:"category"`       // OWASP Category (e.g. CICD-SEC-04)
	RuleID         RuleID   `json:"rule_id"`        // Per-check identifier (matches RuleSpec.ID). Empty for SYSTEM findings.
	Title          string   `json:"title"`          // Short description
	Description    string   `json:"description"`    // Detailed description of the risk
	Recommendation string   `json:"recommendation"` // Actionable steps to fix
	// Confidence is how certain the check is that this finding is real.
	// Backfilled from the rule's DefaultConfidence by StampConfidence; SYSTEM
	// findings (empty RuleID) default to HIGH.
	Confidence Confidence `json:"confidence,omitempty"`
	// Fingerprint is a stable identity for tracking the same finding across
	// scans (independent of line/column shifts). Populated by
	// AssignFingerprints; empty until then. Feeds the web app's new-finding
	// diffing and SARIF partialFingerprints.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Config represents options for scanning.
type Config struct {
	Path           string   `json:"path"`
	FailOnSeverity Severity `json:"fail_on_severity"`
	Ruleset        string   `json:"ruleset"` // "all", "owasp", "slsa", "slsa-build-l1|2|3"
}

// WorkflowNode is a wrapper around the yaml.Node to parse a GitHub Actions workflow.
type WorkflowNode struct {
	Name        yaml.Node `yaml:"name"`
	On          yaml.Node `yaml:"on"`
	Permissions yaml.Node `yaml:"permissions"`
	Env         yaml.Node `yaml:"env"`
	Concurrency yaml.Node `yaml:"concurrency"`
	Jobs        yaml.Node `yaml:"jobs"`
}

// JobNode represents a single job in a workflow.
type JobNode struct {
	Name        yaml.Node `yaml:"name"`
	RunsOn      yaml.Node `yaml:"runs-on"`
	Permissions yaml.Node `yaml:"permissions"`
	Env         yaml.Node `yaml:"env"`
	Concurrency yaml.Node `yaml:"concurrency"`
	Steps       yaml.Node `yaml:"steps"`
	// Uses is a job-level `uses:` — i.e. the job calls a reusable workflow
	// (owner/repo/.github/workflows/x.yml@ref). Empty for normal step-based jobs.
	Uses           yaml.Node `yaml:"uses"`
	If             yaml.Node `yaml:"if"`
	TimeoutMinutes yaml.Node `yaml:"timeout-minutes"`
}

// StepNode represents a single step in a job.
type StepNode struct {
	Name yaml.Node `yaml:"name"`
	Uses yaml.Node `yaml:"uses"`
	Run  yaml.Node `yaml:"run"`
	If   yaml.Node `yaml:"if"`
	Env  yaml.Node `yaml:"env"`
	With yaml.Node `yaml:"with"`
}
