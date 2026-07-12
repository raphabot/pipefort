package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ScanFile scans a single GitHub Actions workflow file from disk.
func ScanFile(filePath string) ([]Finding, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return ScanBytes(filePath, content)
}

// ScanBytes scans raw CI YAML held in memory. It dispatches on the file path:
// .gitlab-ci.yml / .gitlab-ci/*.yml is routed through the GitLab scanner;
// everything else is treated as a GitHub Actions workflow. The name argument
// is used both for dispatch and as the Finding.File label so callers need
// not write content to disk before scanning.
func ScanBytes(name string, content []byte) ([]Finding, error) {
	filePath := name

	if IsGitLabCIPath(filePath) {
		glFindings, err := scanGitLabBytes(filePath, content)
		return applyInlineIgnores(StampConfidence(glFindings), content), err
	}

	var workflow WorkflowNode
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %s: %w", filePath, err)
	}

	// If the file is not a valid workflow (e.g. doesn't have 'jobs' or 'on'), skip it silently
	if workflow.Jobs.Kind == 0 && workflow.On.Kind == 0 {
		return nil, nil
	}

	// Extract jobs
	var jobs []JobNodeWithID
	if workflow.Jobs.Kind == yaml.MappingNode {
		for i := 0; i < len(workflow.Jobs.Content); i += 2 {
			keyNode := workflow.Jobs.Content[i]
			valNode := workflow.Jobs.Content[i+1]

			var job JobNode
			if err := valNode.Decode(&job); err == nil {
				jobs = append(jobs, JobNodeWithID{
					ID:     keyNode.Value,
					Line:   keyNode.Line,
					Column: keyNode.Column,
					Node:   job,
				})
			}
		}
	}

	// Run all checks
	var findings []Finding
	findings = append(findings, CheckPPE(filePath, &workflow, jobs)...)
	findings = append(findings, CheckPBAC(filePath, &workflow, jobs)...)
	findings = append(findings, CheckUnpinnedActions(filePath, &workflow, jobs)...)
	findings = append(findings, CheckUnpinnedImages(filePath, &workflow, jobs)...)
	findings = append(findings, CheckUntrustedPullRequestTarget(filePath, &workflow, jobs)...)
	findings = append(findings, CheckHardcodedSecrets(filePath, &workflow, jobs)...)
	findings = append(findings, CheckPipeToShell(filePath, &workflow, jobs)...)
	findings = append(findings, CheckMissingTimeout(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSelfHostedRunners(filePath, &workflow, jobs)...)

	// Extended OWASP coverage (owasp_extended_rules.go) — CICD-SEC-2/6/7/8/9/10.
	findings = append(findings, CheckLongLivedPAT(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSecretInRunOutput(filePath, &workflow, jobs)...)
	findings = append(findings, CheckDebugLoggingEnabled(filePath, &workflow, jobs)...)
	findings = append(findings, CheckRepoDispatchUnfiltered(filePath, &workflow, jobs)...)
	findings = append(findings, CheckDownloadWithoutChecksum(filePath, &workflow, jobs)...)
	findings = append(findings, CheckContinueOnErrorJob(filePath, &workflow, jobs)...)

	// Privileged-trigger hardening (rules.go) — CICD-SEC-1/4.
	findings = append(findings, CheckWorkflowRunArtifactPoisoning(filePath, &workflow, jobs)...)
	findings = append(findings, CheckCheckoutPersistCredentials(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSecretsInheritPRTarget(filePath, &workflow, jobs)...)

	// Injection-depth checks (injection_rules.go) — CICD-SEC-4/1.
	findings = append(findings, CheckGitHubEnvInjection(filePath, &workflow, jobs)...)
	findings = append(findings, CheckPPELaundered(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSpoofableActorCondition(filePath, &workflow, jobs)...)

	// Offline rule-parity batch (parity_rules.go) — CICD-SEC-1/2/4/6, BEST-PRAC-4.
	findings = append(findings, CheckUnsoundCondition(filePath, &workflow, jobs)...)
	findings = append(findings, CheckUnsoundContains(filePath, &workflow, jobs)...)
	findings = append(findings, CheckObfuscatedExpression(filePath, &workflow, jobs)...)
	findings = append(findings, CheckCachePoisoningRelease(filePath, &workflow, jobs)...)
	findings = append(findings, CheckOverprovisionedSecrets(filePath, &workflow, jobs)...)
	findings = append(findings, CheckUseTrustedPublishing(filePath, &workflow, jobs)...)
	findings = append(findings, CheckMissingConcurrency(filePath, &workflow, jobs)...)

	// SLSA Build-track checks (slsa_rules.go).
	findings = append(findings, CheckSLSAProvenance(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSLSAProvenanceIsolated(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSLSAOIDCTokenScope(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSLSAPermsOverlyBroad(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSLSACachePoisoning(filePath, &workflow, jobs)...)
	findings = append(findings, CheckSLSAVerifyStep(filePath, &workflow, jobs)...)

	return applyInlineIgnores(StampConfidence(findings), content), nil
}

// ScanDir walks a directory looking for CI/CD configs to scan:
//   - .github/workflows/*.yml / *.yaml (GitHub Actions)
//   - .gitlab-ci.yml at the repo root and .gitlab-ci/**/*.yml (GitLab CI)
//
// Both layouts are walked when present; findings from each are merged in
// path order. When neither is present we fall back to the legacy "walk
// everything" behaviour for ad-hoc YAML collections.
func ScanDir(dirPath string) ([]Finding, error) {
	var findings []Finding
	var ghFound, glFound bool

	workflowsDir := filepath.Join(dirPath, ".github", "workflows")
	if info, err := os.Stat(workflowsDir); err == nil && info.IsDir() {
		ghFound = true
		err = filepath.Walk(workflowsDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			fileFindings, scanErr := ScanFile(path)
			if scanErr != nil {
				findings = append(findings, Finding{
					File:           path,
					Line:           1,
					Column:         1,
					Severity:       SeverityInfo,
					Category:       "SYSTEM",
					Title:          "File Parse Error",
					Description:    fmt.Sprintf("Failed to parse workflow file: %v", scanErr),
					Recommendation: "Ensure the file contains valid YAML format.",
				})
				return nil
			}
			findings = append(findings, fileFindings...)
			return nil
		})
		if err != nil {
			return findings, err
		}
	}

	// Root .gitlab-ci.yml + .gitlab-ci/ tree.
	rootGL := []string{".gitlab-ci.yml", ".gitlab-ci.yaml"}
	for _, name := range rootGL {
		p := filepath.Join(dirPath, name)
		if _, err := os.Stat(p); err == nil {
			glFound = true
			fileFindings, scanErr := ScanFile(p)
			if scanErr != nil {
				findings = append(findings, Finding{
					File: p, Line: 1, Column: 1,
					Severity:       SeverityInfo,
					Category:       "SYSTEM",
					Title:          "File Parse Error",
					Description:    fmt.Sprintf("Failed to parse GitLab CI file: %v", scanErr),
					Recommendation: "Ensure the file contains valid YAML format.",
				})
				continue
			}
			findings = append(findings, fileFindings...)
		}
	}
	glDir := filepath.Join(dirPath, ".gitlab-ci")
	if info, err := os.Stat(glDir); err == nil && info.IsDir() {
		glFound = true
		err = filepath.Walk(glDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			fileFindings, scanErr := ScanFile(path)
			if scanErr != nil {
				findings = append(findings, Finding{
					File: path, Line: 1, Column: 1,
					Severity:       SeverityInfo,
					Category:       "SYSTEM",
					Title:          "File Parse Error",
					Description:    fmt.Sprintf("Failed to parse GitLab CI file: %v", scanErr),
					Recommendation: "Ensure the file contains valid YAML format.",
				})
				return nil
			}
			findings = append(findings, fileFindings...)
			return nil
		})
		if err != nil {
			return findings, err
		}
	}

	if !ghFound && !glFound {
		return scanDirectoryFallback(dirPath)
	}
	return findings, nil
}

// scanDirectoryFallback scans all .yml/yaml files recursively under the given directory
// if no .github/workflows folder was found. This allows scanning random collections of workflow files.
func scanDirectoryFallback(dirPath string) ([]Finding, error) {
	var findings []Finding
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Skip hidden directories (like .git, etc.)
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." && info.Name() != ".." {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yml" || ext == ".yaml" {
			fileFindings, scanErr := ScanFile(path)
			if scanErr != nil {
				// Skip parsing errors in fallback mode as they might not be workflow files
				return nil
			}
			findings = append(findings, fileFindings...)
		}
		return nil
	})

	return findings, err
}

// FilterFindings filters findings based on the ruleset. Supported values:
//
//   - "", "all"                — every finding (no filter).
//   - "owasp"                  — rules tagged with FrameworkOWASP.
//   - "slsa"                   — rules tagged with any SLSA v1.2 framework (Build or Source track).
//   - "slsa-build-l1|l2|l3"    — rules for that specific SLSA v1.2 Build level.
//   - "slsa-source-l1|l2|l3|l4" — rules for that specific SLSA v1.2 Source level.
//
// SYSTEM findings (no RuleID — parse errors, settings-audit notices) always
// pass. Rules with no framework tags only appear under "all".
func FilterFindings(findings []Finding, ruleset string) []Finding {
	ruleset = strings.ToLower(strings.TrimSpace(ruleset))
	if ruleset == "" || ruleset == "all" {
		return findings
	}
	byID := RuleByID()
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == "" {
			// SYSTEM/parse-error findings have no rule id and are never filtered out.
			out = append(out, f)
			continue
		}
		spec, ok := byID[f.RuleID]
		if !ok {
			continue
		}
		if frameworkMatches(spec.Frameworks, ruleset) {
			out = append(out, f)
		}
	}
	return out
}

// frameworkMatches reports whether a rule's framework list satisfies the given
// ruleset filter. "slsa" is sugar for any slsa-* entry.
func frameworkMatches(frameworks []string, ruleset string) bool {
	if ruleset == "slsa" {
		for _, f := range frameworks {
			if strings.HasPrefix(f, "slsa-") {
				return true
			}
		}
		return false
	}
	for _, f := range frameworks {
		if f == ruleset {
			return true
		}
	}
	return false
}
