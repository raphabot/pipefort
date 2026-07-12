package scanner

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// IsGitLabCIPath reports whether a path looks like a GitLab CI config file:
// .gitlab-ci.yml / .gitlab-ci.yaml at the repo root, or any *.yml/.yaml under
// .gitlab-ci/.
func IsGitLabCIPath(p string) bool {
	base := filepath.Base(p)
	if base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml" {
		return true
	}
	lower := strings.ToLower(p)
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	// Match both ".gitlab-ci/foo.yml" and ".gitlab-ci/sub/foo.yml" but not
	// random paths containing the substring elsewhere.
	if strings.HasPrefix(p, ".gitlab-ci/") {
		return true
	}
	idx := strings.Index(p, "/.gitlab-ci/")
	return idx >= 0
}

// scanGitLabBytes is the GitLab CI sibling of scanGitHubBytes (inlined into
// ScanBytes). It unmarshals .gitlab-ci.yml into the GitLab AST and runs the
// gitlab rule list.
func scanGitLabBytes(filePath string, content []byte) ([]Finding, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %s: %w", filePath, err)
	}
	root := topMapping(&doc)
	if root == nil {
		return nil, nil
	}

	jobs, vars := splitGitLabRoot(root)
	if len(jobs) == 0 && vars == nil {
		// Doesn't look like a GitLab pipeline file (no jobs, no variables).
		return nil, nil
	}

	var out []Finding
	out = append(out, checkGitLabMRTarget(filePath, jobs)...)
	out = append(out, checkGitLabPATSecret(filePath, jobs, vars)...)
	out = append(out, checkGitLabUnpinnedInclude(filePath, root)...)
	out = append(out, checkGitLabShellInjection(filePath, jobs)...)
	out = append(out, checkGitLabHardcodedSecrets(filePath, jobs, vars)...)
	out = append(out, checkGitLabDebugTrace(filePath, jobs, vars)...)
	out = append(out, checkGitLabTriggerUnfiltered(filePath, jobs)...)
	out = append(out, checkGitLabAllowFailure(filePath, jobs)...)
	out = append(out, checkGitLabMissingTimeout(filePath, root, jobs)...)
	out = append(out, checkGitLabSelfHostedTags(filePath, jobs)...)
	out = append(out, checkGitLabMissingResourceGroup(filePath, jobs)...)

	// Portable rules (same RuleID as the GitHub variant — best-prac-1 and
	// cicd-sec-9). The portable check operates on script-line slices we
	// extract from the GitLab job tree.
	out = append(out, checkGitLabPipeToShell(filePath, jobs)...)
	out = append(out, checkGitLabDownloadNoChecksum(filePath, jobs)...)

	return out, nil
}

// glJob is a parsed view of one GitLab job mapping. Only the keys our rules
// inspect are pulled into typed fields; the raw mapping is kept for line/col
// access during finding emission.
type glJob struct {
	ID        string
	Key       *yaml.Node // mapping-entry key (the job name)
	Mapping   *yaml.Node // value (the job mapping node)
	Script    []scriptLine
	Before    []scriptLine
	After     []scriptLine
	Rules     *yaml.Node
	Only      *yaml.Node
	Tags      *yaml.Node
	Image     *yaml.Node
	Vars      *yaml.Node
	Timeout   *yaml.Node
	AllowFail *yaml.Node
	Trigger   *yaml.Node
}

// scriptLine is a single string in a script:/before_script:/after_script:
// sequence, preserving its line/column for finding emission.
type scriptLine struct {
	Text   string
	Line   int
	Column int
}

// topMapping returns the document's root mapping node, or nil if the YAML
// isn't a mapping at top level.
func topMapping(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return topMapping(doc.Content[0])
	}
	if doc.Kind == yaml.MappingNode {
		return doc
	}
	return nil
}

// splitGitLabRoot iterates the top-level mapping and partitions entries into
// jobs (anything that looks like a job mapping with script/trigger/extends)
// vs the special top-level "variables" / "default" / "include" / etc.
//
// In GitLab CI any top-level key that isn't a reserved keyword is treated as
// a job. We use a simple reserved-name set rather than try to detect job
// shape via heuristics — this matches GitLab's own parser behavior more
// closely and avoids false negatives.
func splitGitLabRoot(root *yaml.Node) (jobs []glJob, variables *yaml.Node) {
	reserved := map[string]bool{
		"stages": true, "variables": true, "default": true, "include": true,
		"workflow": true, "image": true, "services": true, "before_script": true,
		"after_script": true, "cache": true, "pages": true, "types": true,
	}
	for i := 0; i < len(root.Content); i += 2 {
		k := root.Content[i]
		v := root.Content[i+1]
		key := k.Value
		if key == "variables" {
			variables = v
			continue
		}
		if reserved[key] {
			continue
		}
		// Keys starting with "." are hidden/template jobs in GitLab; skip.
		if strings.HasPrefix(key, ".") {
			continue
		}
		if v.Kind != yaml.MappingNode {
			continue
		}
		job := glJob{ID: key, Key: k, Mapping: v}
		for j := 0; j < len(v.Content); j += 2 {
			jk := v.Content[j]
			jv := v.Content[j+1]
			switch jk.Value {
			case "script":
				job.Script = extractScriptLines(jv)
			case "before_script":
				job.Before = extractScriptLines(jv)
			case "after_script":
				job.After = extractScriptLines(jv)
			case "rules":
				job.Rules = jv
			case "only":
				job.Only = jv
			case "tags":
				job.Tags = jv
			case "image":
				job.Image = jv
			case "variables":
				job.Vars = jv
			case "timeout":
				job.Timeout = jv
			case "allow_failure":
				job.AllowFail = jv
			case "trigger":
				job.Trigger = jv
			}
		}
		jobs = append(jobs, job)
	}
	return jobs, variables
}

// extractScriptLines flattens a script: value (string OR sequence of strings
// OR sequence of strings-and-maps) into a slice of scriptLine.
func extractScriptLines(n *yaml.Node) []scriptLine {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return []scriptLine{{Text: n.Value, Line: n.Line, Column: n.Column}}
	case yaml.SequenceNode:
		var out []scriptLine
		for _, item := range n.Content {
			if item.Kind == yaml.ScalarNode {
				out = append(out, scriptLine{Text: item.Value, Line: item.Line, Column: item.Column})
				continue
			}
			// In GitLab a step can also be a mapping (e.g. !reference [...]).
			// Skip those — we can't statically analyse the referenced text.
		}
		return out
	}
	return nil
}

// mappingValueByKey looks up a child of a mapping node by its string key.
func mappingValueByKey(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------

// CICD-SEC-1 (GitLab) — jobs that run on merge_request_event AND check out the
// MR source ref via $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME or
// $CI_MERGE_REQUEST_SOURCE_PROJECT_PATH in a way that exposes pipeline
// secrets to attacker-controlled code.
func checkGitLabMRTarget(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		if !jobRunsOnMR(job) {
			continue
		}
		// Heuristic: a job tagged for MR events that explicitly checks out the
		// MR source branch (git checkout/fetch of MR head) is the dangerous
		// pattern. The default `git clone` GitLab does for the MR ref is
		// already the source branch, so flag overrides that re-fetch the
		// head ref directly via the source-branch env vars.
		for _, line := range allScripts(job) {
			low := strings.ToLower(line.Text)
			if (strings.Contains(low, "git fetch") || strings.Contains(low, "git checkout") || strings.Contains(low, "git pull")) &&
				(strings.Contains(line.Text, "$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA") ||
					strings.Contains(line.Text, "${CI_MERGE_REQUEST_SOURCE_BRANCH_SHA}") ||
					strings.Contains(line.Text, "$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME") ||
					strings.Contains(line.Text, "${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME}")) {
				out = append(out, Finding{
					File: filePath, Line: line.Line, Column: line.Column,
					Severity: SeverityHigh, Category: "CICD-SEC-1",
					RuleID:         RuleGitLabMRTarget,
					Title:          "Job runs untrusted MR code with pipeline secrets",
					Description:    fmt.Sprintf("Job %q runs on merge_request_event and explicitly checks out the MR source ref in `script`. Pipeline CI variables (including masked secrets) are exposed to attacker-controlled code.", job.ID),
					Recommendation: "Restrict the job to trusted branches via `rules:` (e.g. `$CI_PIPELINE_SOURCE == \"push\"`), and use the protected `merge_request_event` integration with the `protected: true` flag on CI variables that hold secrets.",
				})
				break // one finding per job
			}
		}
	}
	return out
}

func jobRunsOnMR(job glJob) bool {
	// Heuristic: any `rules:` or `only:` mention of "merge_request" suggests
	// the job participates in MR pipelines.
	check := func(n *yaml.Node) bool {
		if n == nil {
			return false
		}
		return strings.Contains(strings.ToLower(nodeText(n)), "merge_request")
	}
	return check(job.Rules) || check(job.Only)
}

// nodeText returns a flat string rendering of a yaml.Node for substring
// inspection. Cheap and good-enough for the heuristic checks here.
func nodeText(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var b strings.Builder
	for _, c := range n.Content {
		b.WriteString(nodeText(c))
		b.WriteString(" ")
	}
	return b.String()
}

// CICD-SEC-2 (GitLab) — flags CI variables whose names look like long-lived
// personal/group access tokens rather than the short-lived CI_JOB_TOKEN.
var glPATName = regexp.MustCompile(`(?i)(?:^|_)(pat|personal[_-]?access[_-]?token|gitlab[_-]?token|group[_-]?token)(?:$|_)`)

func checkGitLabPATSecret(filePath string, jobs []glJob, topVars *yaml.Node) []Finding {
	var out []Finding
	emit := func(line, col int, name string) {
		out = append(out, Finding{
			File: filePath, Line: line, Column: col,
			Severity: SeverityMedium, Category: "CICD-SEC-2",
			RuleID:         RuleGitLabPATSecret,
			Title:          "Long-lived access token used in pipeline",
			Description:    fmt.Sprintf("CI variable %q matches the shape of a long-lived personal/group access token. Long-lived credentials are a high-value target if logs or build artifacts leak.", name),
			Recommendation: "Replace with the short-lived `$CI_JOB_TOKEN` where possible, or rotate to a project access token with the smallest scope and shortest expiry your workflow allows.",
		})
	}
	check := func(vars *yaml.Node) {
		if vars == nil || vars.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i < len(vars.Content); i += 2 {
			k := vars.Content[i]
			if glPATName.MatchString(k.Value) {
				emit(k.Line, k.Column, k.Value)
			}
		}
	}
	check(topVars)
	for _, job := range jobs {
		check(job.Vars)
	}
	return out
}

// CICD-SEC-3 (GitLab) — flags include: of remote templates/projects without
// a SHA-pinned ref.
func checkGitLabUnpinnedInclude(filePath string, root *yaml.Node) []Finding {
	inc := mappingValueByKey(root, "include")
	if inc == nil {
		return nil
	}
	var out []Finding
	visit := func(item *yaml.Node) {
		if item == nil {
			return
		}
		switch item.Kind {
		case yaml.ScalarNode:
			// `include: '/path'` (local) or `include: 'https://...'` (remote
			// URL without ref). The remote variants are unpinned by
			// definition because GitLab fetches HEAD.
			if strings.HasPrefix(strings.ToLower(item.Value), "http") {
				out = append(out, Finding{
					File: filePath, Line: item.Line, Column: item.Column,
					Severity: SeverityMedium, Category: "CICD-SEC-3",
					RuleID:         RuleGitLabUnpinnedInclude,
					Title:          "Remote include without pinned ref",
					Description:    "Remote URL includes always fetch HEAD of the upstream template — a supply-chain risk if the upstream is compromised or rolls back a security fix.",
					Recommendation: "Use `include: project:` with an explicit `ref:` pinned to a 40-char commit SHA, or vendor the template into your repo.",
				})
			}
		case yaml.MappingNode:
			project := mappingValueByKey(item, "project")
			ref := mappingValueByKey(item, "ref")
			template := mappingValueByKey(item, "template")
			remote := mappingValueByKey(item, "remote")
			if template != nil {
				// `include: template:` ships with GitLab and is curated.
				return
			}
			if remote != nil {
				// `include: { remote: 'https://...' }` always fetches HEAD of
				// the upstream URL — unpinned by definition.
				out = append(out, Finding{
					File: filePath, Line: remote.Line, Column: remote.Column,
					Severity: SeverityMedium, Category: "CICD-SEC-3",
					RuleID:         RuleGitLabUnpinnedInclude,
					Title:          "Remote include without pinned ref",
					Description:    "Remote URL includes always fetch HEAD of the upstream template — a supply-chain risk if the upstream is compromised or rolls back a security fix.",
					Recommendation: "Use `include: project:` with an explicit `ref:` pinned to a 40-char commit SHA, or vendor the template into your repo.",
				})
				return
			}
			if project != nil {
				if ref == nil {
					out = append(out, Finding{
						File: filePath, Line: project.Line, Column: project.Column,
						Severity: SeverityMedium, Category: "CICD-SEC-3",
						RuleID:         RuleGitLabUnpinnedInclude,
						Title:          "Project include without pinned ref",
						Description:    fmt.Sprintf("`include: project:` of %q has no `ref:` — GitLab fetches HEAD of the upstream default branch.", project.Value),
						Recommendation: "Add `ref: <40-char-SHA>` so the included template is immutable.",
					})
					return
				}
				if !looksLikeSHA(ref.Value) {
					out = append(out, Finding{
						File: filePath, Line: ref.Line, Column: ref.Column,
						Severity: SeverityLow, Category: "CICD-SEC-3",
						RuleID:         RuleGitLabUnpinnedInclude,
						Title:          "Project include pinned to a mutable ref",
						Description:    fmt.Sprintf("`include: project:` of %q is pinned to %q, which is a branch or tag (mutable).", project.Value, ref.Value),
						Recommendation: "Replace the ref with a 40-character commit SHA.",
					})
				}
			}
		}
	}
	switch inc.Kind {
	case yaml.SequenceNode:
		for _, item := range inc.Content {
			visit(item)
		}
	default:
		visit(inc)
	}
	return out
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func looksLikeSHA(s string) bool { return shaRe.MatchString(strings.ToLower(s)) }

// CICD-SEC-4 (GitLab) — flags script lines that interpolate attacker-
// controlled $CI_MERGE_REQUEST_* / $CI_COMMIT_* metadata directly into the
// shell without going through an env-var redirection.
var glAttackerControlled = []string{
	"$CI_MERGE_REQUEST_TITLE",
	"$CI_MERGE_REQUEST_DESCRIPTION",
	"$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"$CI_COMMIT_MESSAGE",
	"$CI_COMMIT_TITLE",
	"${CI_MERGE_REQUEST_TITLE}",
	"${CI_MERGE_REQUEST_DESCRIPTION}",
	"${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME}",
	"${CI_COMMIT_MESSAGE}",
	"${CI_COMMIT_TITLE}",
}

func checkGitLabShellInjection(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		for _, line := range allScripts(job) {
			for _, expr := range glAttackerControlled {
				if strings.Contains(line.Text, expr) {
					out = append(out, Finding{
						File: filePath, Line: line.Line, Column: line.Column,
						Severity: SeverityHigh, Category: "CICD-SEC-4",
						RuleID:         RuleGitLabShellInjection,
						Title:          "Untrusted MR/commit metadata interpolated into shell",
						Description:    fmt.Sprintf("Script in job %q interpolates %s directly into the shell. An attacker controlling MR title/description/branch name can inject arbitrary commands.", job.ID, expr),
						Recommendation: "Move the value into the job's `variables:` (or `env:` for the step) and reference it via a shell variable, e.g. `TITLE: $CI_MERGE_REQUEST_TITLE` then `\"$TITLE\"` in the script.",
					})
					break
				}
			}
		}
	}
	return out
}

// CICD-SEC-6 (GitLab) — high-entropy or known-shape token literals inline in
// variables:. Mirrors the GitHub hardcoded-secrets check but on the GitLab
// variable shape.
var (
	glAWSAccessKey = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	glSlackToken   = regexp.MustCompile(`xox[abprs]-[0-9A-Za-z-]{10,}`)
	glGHPAT        = regexp.MustCompile(`(?:ghp|ghu|gho|ghs|ghr)_[A-Za-z0-9]{30,}`)
	glGLPAT        = regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`)
)

func checkGitLabHardcodedSecrets(filePath string, jobs []glJob, topVars *yaml.Node) []Finding {
	var out []Finding
	emit := func(n *yaml.Node, name string) {
		out = append(out, Finding{
			File: filePath, Line: n.Line, Column: n.Column,
			Severity: SeverityHigh, Category: "CICD-SEC-6",
			RuleID:         RuleGitLabHardcodedSecrets,
			Title:          "Hardcoded credential in pipeline variables",
			Description:    fmt.Sprintf("CI variable %q contains a literal that matches a known credential shape.", name),
			Recommendation: "Move the value into a masked CI/CD variable configured in GitLab project settings and reference it by name in the YAML.",
		})
	}
	check := func(vars *yaml.Node) {
		if vars == nil || vars.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i < len(vars.Content); i += 2 {
			k := vars.Content[i]
			v := vars.Content[i+1]
			val := ""
			switch v.Kind {
			case yaml.ScalarNode:
				val = v.Value
			case yaml.MappingNode:
				// GitLab allows {value: "...", description: "..."} per variable.
				if inner := mappingValueByKey(v, "value"); inner != nil && inner.Kind == yaml.ScalarNode {
					val = inner.Value
				}
			}
			if val == "" {
				continue
			}
			if glAWSAccessKey.MatchString(val) || glSlackToken.MatchString(val) ||
				glGHPAT.MatchString(val) || glGLPAT.MatchString(val) {
				emit(k, k.Value)
			}
		}
	}
	check(topVars)
	for _, job := range jobs {
		check(job.Vars)
	}
	return out
}

// CICD-SEC-7 (GitLab) — flag CI_DEBUG_TRACE / CI_DEBUG_SERVICES set to true.
func checkGitLabDebugTrace(filePath string, jobs []glJob, topVars *yaml.Node) []Finding {
	var out []Finding
	emit := func(n *yaml.Node, name string) {
		out = append(out, Finding{
			File: filePath, Line: n.Line, Column: n.Column,
			Severity: SeverityHigh, Category: "CICD-SEC-7",
			RuleID:         RuleGitLabDebugTrace,
			Title:          "Pipeline debug logging enabled",
			Description:    fmt.Sprintf("%s is enabled — GitLab will log expanded values of every CI variable, including masked secrets, to job logs visible to anyone with Reporter access.", name),
			Recommendation: "Remove the variable. If you need to debug, enable it temporarily on a single pipeline run via the GitLab UI rather than committing it to YAML.",
		})
	}
	check := func(vars *yaml.Node) {
		if vars == nil || vars.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i < len(vars.Content); i += 2 {
			k := vars.Content[i]
			v := vars.Content[i+1]
			if k.Value != "CI_DEBUG_TRACE" && k.Value != "CI_DEBUG_SERVICES" {
				continue
			}
			val := ""
			if v.Kind == yaml.ScalarNode {
				val = v.Value
			} else if inner := mappingValueByKey(v, "value"); inner != nil {
				val = inner.Value
			}
			if isTruthy(val) {
				emit(k, k.Value)
			}
		}
	}
	check(topVars)
	for _, job := range jobs {
		check(job.Vars)
	}
	return out
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// CICD-SEC-8 (GitLab) — flags pipeline-triggered jobs whose `rules:` allow
// $CI_PIPELINE_SOURCE == "trigger" or "pipeline" without an additional
// filter (e.g. an allowlist of upstream branches/projects).
func checkGitLabTriggerUnfiltered(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		text := nodeText(job.Rules) + " " + nodeText(job.Only)
		low := strings.ToLower(text)
		mentionsTrigger := strings.Contains(low, `"trigger"`) || strings.Contains(low, `"pipeline"`) ||
			strings.Contains(low, "$ci_pipeline_source == \"trigger\"") ||
			strings.Contains(low, "$ci_pipeline_source == \"pipeline\"")
		if !mentionsTrigger {
			continue
		}
		// Require either a ref filter (CI_COMMIT_REF_NAME / CI_COMMIT_BRANCH)
		// or an upstream-project filter (CI_PROJECT_PATH / CI_PROJECT_ID) to
		// consider it scoped. Otherwise warn.
		hasFilter := strings.Contains(low, "ci_commit_ref_name") ||
			strings.Contains(low, "ci_commit_branch") ||
			strings.Contains(low, "ci_project_path") ||
			strings.Contains(low, "ci_project_id")
		if hasFilter {
			continue
		}
		line, col := jobRulesAnchor(job)
		out = append(out, Finding{
			File: filePath, Line: line, Column: col,
			Severity: SeverityMedium, Category: "CICD-SEC-8",
			RuleID:         RuleGitLabTriggerUnfiltered,
			Title:          "Trigger pipeline accepted from any source",
			Description:    fmt.Sprintf("Job %q runs on external trigger / pipeline events without restricting the upstream project or branch — any holder of a trigger token can run it.", job.ID),
			Recommendation: "Add an explicit allowlist to `rules:`, e.g. `$CI_PROJECT_PATH == \"group/known-project\"` or `$CI_COMMIT_REF_NAME == \"main\"`.",
		})
	}
	return out
}

// CICD-SEC-10 (GitLab) — flags job-level allow_failure: true. Pipeline status
// hides the failure from required-status gates.
func checkGitLabAllowFailure(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		if job.AllowFail == nil {
			continue
		}
		// Only flag literal-true. Conditional allow_failure (a mapping with
		// `exit_codes:`) is intentionally narrow and OK.
		if job.AllowFail.Kind != yaml.ScalarNode {
			continue
		}
		if strings.ToLower(job.AllowFail.Value) != "true" {
			continue
		}
		out = append(out, Finding{
			File: filePath, Line: job.AllowFail.Line, Column: job.AllowFail.Column,
			Severity: SeverityLow, Category: "CICD-SEC-10",
			RuleID:         RuleGitLabAllowFailure,
			Title:          "Job declares allow_failure: true",
			Description:    fmt.Sprintf("Job %q sets allow_failure: true. Pipeline status reports success even if the job fails — required-status gates and audit dashboards never see it.", job.ID),
			Recommendation: "Remove allow_failure or narrow it to specific exit codes via `allow_failure: { exit_codes: [...] }`.",
		})
	}
	return out
}

// BEST-PRAC-2 (GitLab) — flags jobs that omit `timeout:` and don't inherit
// one from `default:`.
func checkGitLabMissingTimeout(filePath string, root *yaml.Node, jobs []glJob) []Finding {
	defaultTimeout := false
	if def := mappingValueByKey(root, "default"); def != nil {
		if mappingValueByKey(def, "timeout") != nil {
			defaultTimeout = true
		}
	}
	if defaultTimeout {
		return nil
	}
	var out []Finding
	for _, job := range jobs {
		if job.Timeout != nil {
			continue
		}
		// Trigger jobs (downstream pipelines) don't honour `timeout:`.
		if job.Trigger != nil {
			continue
		}
		out = append(out, Finding{
			File: filePath, Line: job.Key.Line, Column: job.Key.Column,
			Severity: SeverityLow, Category: "BEST-PRAC-2",
			RuleID:         RuleGitLabMissingTimeout,
			Title:          "Job has no timeout configured",
			Description:    fmt.Sprintf("Job %q has no `timeout:` set and `default:` doesn't supply one — a stuck job will run for the project's instance maximum (default 1h, configurable up to 1mo).", job.ID),
			Recommendation: "Add `timeout: 30m` (or a value appropriate for the job) at the job level, or set a global `default: { timeout: 30m }`.",
		})
	}
	return out
}

// BEST-PRAC-3 (GitLab) — flags jobs whose `tags:` target a non-SaaS shared
// runner (i.e. a self-hosted/project-specific runner).
var saasRunnerTagRe = regexp.MustCompile(`^saas-`)

// checkGitLabMissingResourceGroup flags deploy jobs (an `environment:` key)
// that declare no `resource_group:`, so concurrent pipelines can deploy to the
// same environment at once — the GitLab analog of best-prac-4 concurrency.
func checkGitLabMissingResourceGroup(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		if job.Mapping == nil || mappingValueByKey(job.Mapping, "environment") == nil {
			continue
		}
		if mappingValueByKey(job.Mapping, "resource_group") != nil {
			continue
		}
		out = append(out, Finding{
			File: filePath, Line: job.Key.Line, Column: job.Key.Column,
			Severity: SeverityLow, Category: "BEST-PRAC-4",
			RuleID:         RuleGitLabMissingResGroup,
			Title:          "GitLab deploy job has no resource_group",
			Description:    fmt.Sprintf("Job %q defines an `environment:` (a deployment) but no `resource_group:`, so concurrent pipelines can deploy to it simultaneously and race on the target.", job.ID),
			Recommendation: "Add `resource_group: <environment-name>` to serialize deployments to this environment.",
		})
	}
	return out
}

func checkGitLabSelfHostedTags(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		if job.Tags == nil || job.Tags.Kind != yaml.SequenceNode {
			continue
		}
		var nonSaaS []string
		for _, t := range job.Tags.Content {
			if t.Kind != yaml.ScalarNode {
				continue
			}
			if saasRunnerTagRe.MatchString(t.Value) {
				continue
			}
			nonSaaS = append(nonSaaS, t.Value)
		}
		if len(nonSaaS) == 0 {
			continue
		}
		out = append(out, Finding{
			File: filePath, Line: job.Tags.Line, Column: job.Tags.Column,
			Severity: SeverityLow, Category: "BEST-PRAC-3",
			RuleID:         RuleGitLabSelfHostedTags,
			Title:          "Job targets a self-hosted runner",
			Description:    fmt.Sprintf("Job %q runs on tags %v that are not SaaS-shared runners. Self-hosted runners may bridge to internal infrastructure if exposed to untrusted MRs.", job.ID, nonSaaS),
			Recommendation: "Confirm the runner is dedicated, doesn't run on protected branches alongside untrusted code, and has network egress restricted. Consider a `saas-linux-medium-amd64` shared runner for non-sensitive jobs.",
		})
	}
	return out
}

// pipeToShellRe matches a network fetch piped straight into an interpreter.
// Portable: shared by best-prac-1 on both GitHub (CheckPipeToShell) and GitLab
// (checkGitLabPipeToShell) because the structural pattern is identical across
// CI platforms. Covers three shapes of "fetch a remote script and run it":
//   - pipe form:   curl … | sh   (optional sudo; sh/bash/zsh/dash/python/…/iex)
//   - process sub: bash <(curl …) / sh -c "$(curl …)"
//   - PowerShell:  iex(iwr …) / iex (New-Object …).DownloadString(…)
var pipeToShellRe = regexp.MustCompile(`(?i)(` +
	// curl|wget|iwr … | interpreter
	`(curl|wget|iwr|invoke-webrequest)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|ksh|dash|python3?|iex|node|perl|ruby)\b` +
	`|` +
	// interpreter <(curl …)  or  interpreter -c "$(curl …)"
	`(sh|bash|zsh|ksh|dash|python3?|node|perl|ruby)\b[^\n]*(<\(|-c\s*["']?\$\()\s*(curl|wget)\b` +
	`|` +
	// PowerShell: iex( … iwr/DownloadString … )
	`iex\s*\(?[^)\n]*(iwr|invoke-webrequest|downloadstring)` +
	`)`)

func checkGitLabPipeToShell(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		for _, line := range allScripts(job) {
			if pipeToShellRe.MatchString(line.Text) {
				out = append(out, Finding{
					File: filePath, Line: line.Line, Column: line.Column,
					Severity: SeverityHigh, Category: "BEST-PRAC-1",
					RuleID:         RulePipeToShell,
					Title:          "Command piped directly to shell",
					Description:    fmt.Sprintf("Job %q pipes the output of a network fetch directly into a shell — the executed payload is whatever the server returns at that moment.", job.ID),
					Recommendation: "Download to a file, verify a published checksum or signature, then execute the verified content.",
				})
				break
			}
		}
	}
	return out
}

// Portable: cicd-sec-9 (download-without-checksum). Same RuleID as the
// GitHub variant.
var (
	downloadBinaryRe = regexp.MustCompile(`(?i)(curl|wget)\s+[^|;\n]*\.(tar\.gz|tgz|zip|tar\.xz|tar\.bz2|7z|exe|pkg|dmg|deb|rpm|whl|jar|so|dylib|dll)\b`)
	verifierRe       = regexp.MustCompile(`(?i)\b(sha256sum|sha512sum|gpg\s+--verify|cosign\s+verify|slsa-verifier|openssl\s+dgst|shasum\s+-a)\b`)
)

func checkGitLabDownloadNoChecksum(filePath string, jobs []glJob) []Finding {
	var out []Finding
	for _, job := range jobs {
		lines := allScripts(job)
		// Concatenate the job's full script context so a checksum verifier
		// later in the same job satisfies an earlier download.
		var joined strings.Builder
		for _, l := range lines {
			joined.WriteString(l.Text)
			joined.WriteString("\n")
		}
		joinedStr := joined.String()
		hasVerifier := verifierRe.MatchString(joinedStr)
		if hasVerifier {
			continue
		}
		for _, line := range lines {
			if downloadBinaryRe.MatchString(line.Text) {
				out = append(out, Finding{
					File: filePath, Line: line.Line, Column: line.Column,
					Severity: SeverityMedium, Category: "CICD-SEC-9",
					RuleID:         RuleDownloadNoChecksum,
					Title:          "Downloaded artifact has no integrity check",
					Description:    fmt.Sprintf("Job %q downloads a binary/archive without verifying its checksum, signature, or attestation in the same job.", job.ID),
					Recommendation: "Pin to a SHA-256 / signature / Sigstore attestation. Use `sha256sum -c`, `cosign verify`, or `slsa-verifier verify-artifact` after the download.",
				})
				break
			}
		}
	}
	return out
}

// jobRulesAnchor returns a line/col anchor for a rules-related finding. We
// prefer the rules: node when present, else the job key.
func jobRulesAnchor(job glJob) (int, int) {
	if job.Rules != nil {
		return job.Rules.Line, job.Rules.Column
	}
	if job.Only != nil {
		return job.Only.Line, job.Only.Column
	}
	return job.Key.Line, job.Key.Column
}

// allScripts returns the concatenation of before_script + script + after_script
// for one job. Used by the line-pattern checks.
func allScripts(job glJob) []scriptLine {
	var out []scriptLine
	out = append(out, job.Before...)
	out = append(out, job.Script...)
	out = append(out, job.After...)
	return out
}
