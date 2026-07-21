package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

// Online supply-chain audits of *pinned* actions (CICD-SEC-3). Unlike the
// offline ScanBytes checks, these need network access to api.github.com (and a
// token to avoid low anonymous rate limits), so they run as a separate, opt-in
// pass: the CLI's `--audit-pins` flag and the web scan pipeline (which already
// holds an installation token). The pass never runs inline in ScanBytes, which
// must stay pure for the serverless per-repo web scans.
//
// Four audits:
//   - known-vulnerable-action  — the pinned version is in a published GHSA range
//   - impostor-commit          — a SHA pin that doesn't exist in the claimed repo
//   - ref-version-mismatch     — a SHA pin whose `# vX` comment names a different commit
//   - typosquat-action         — owner/repo is a near-miss of a popular action

var reSHA40 = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

// reVersionToken extracts a version-like token (v1, v1.2, 1.2.3) from a uses:
// line comment so a SHA pin's documented version can be checked.
var reVersionToken = regexp.MustCompile(`v?\d+(\.\d+){0,2}`)

// Ref kinds distinguish a step-level action call from a job-level reusable
// workflow call. Both are `uses:` references but live at different levels and
// mean different things for inventory.
const (
	RefKindAction           = "action"
	RefKindReusableWorkflow = "reusable-workflow"
)

// ActionRef is a single third-party `uses: owner/repo[/path]@ref` reference,
// with the trailing line comment captured for ref-version-mismatch.
type ActionRef struct {
	File           string
	Line           int
	Column         int
	Owner          string
	Repo           string
	Ref            string // tag, branch, or 40-hex SHA after '@'
	Raw            string // full "owner/repo@ref" as written
	VersionComment string // trailing "# v3" comment text, if any
	// Kind is RefKindAction for a step-level action, or RefKindReusableWorkflow
	// for a job-level reusable-workflow call. Empty on refs from callers that
	// predate this field; treat empty as RefKindAction.
	Kind string
	// Path is the reusable workflow's path within its repo (e.g.
	// ".github/workflows/build.yml"). Empty for actions.
	Path string
}

// Advisory is a minimal view of a GitHub security advisory affecting an action.
type Advisory struct {
	GHSAID          string
	Summary         string
	VulnerableRange string // e.g. "< 1.2.3" or ">= 1.0.0, < 1.2.3"
	FirstPatched    string // e.g. "1.2.3" ("" if none)
}

// PinAuditor performs the network lookups the online audits need. It is an
// interface so the audits can be unit-tested with a fake (no network).
type PinAuditor interface {
	// ResolveRef returns the commit SHA a ref (tag/branch/sha) resolves to in
	// owner/repo, and whether it exists there at all (found=false on 404).
	ResolveRef(ctx context.Context, owner, repo, ref string) (sha string, found bool, err error)
	// Advisories returns published advisories affecting the owner/repo action.
	Advisories(ctx context.Context, owner, repo string) ([]Advisory, error)
	// RepoArchived reports whether owner/repo is archived (read-only) upstream.
	// ok=false when the repo can't be read (404/error) so the caller skips it.
	RepoArchived(ctx context.Context, owner, repo string) (archived bool, ok bool, err error)
	// RefKinds reports whether a ref exists upstream as a branch and/or a tag.
	RefKinds(ctx context.Context, owner, repo, ref string) (isBranch, isTag bool, err error)
	// TagSHAs returns the commit SHAs that owner/repo's tags point at.
	TagSHAs(ctx context.Context, owner, repo string) ([]string, error)
}

// CollectActionRefs extracts every third-party action reference from a parsed
// workflow. Local (`./`, `.github/`) and `docker://` references are skipped —
// the former isn't third-party, the latter is handled by CheckUnpinnedImages.
func CollectActionRefs(file string, workflow *WorkflowNode, jobs []JobNodeWithID) []ActionRef {
	var refs []ActionRef
	for _, jobWrap := range jobs {
		if jobWrap.Node.Steps.Kind != yaml.SequenceNode {
			continue
		}
		var steps []StepNode
		if err := jobWrap.Node.Steps.Decode(&steps); err != nil {
			continue
		}
		for _, step := range steps {
			val := step.Uses.Value
			if val == "" || strings.HasPrefix(val, "./") || strings.HasPrefix(val, ".github/") || strings.HasPrefix(val, "docker://") {
				continue
			}
			at := strings.SplitN(val, "@", 2)
			if len(at) != 2 {
				continue
			}
			repoParts := strings.Split(at[0], "/")
			if len(repoParts) < 2 {
				continue
			}
			refs = append(refs, ActionRef{
				File:           file,
				Line:           step.Uses.Line,
				Column:         step.Uses.Column,
				Owner:          repoParts[0],
				Repo:           repoParts[1],
				Ref:            at[1],
				Raw:            val,
				VersionComment: strings.TrimSpace(strings.TrimLeft(step.Uses.LineComment, "# ")),
				Kind:           RefKindAction,
			})
		}
	}
	return refs
}

// CollectReusableWorkflowRefs extracts every remote reusable-workflow call from
// a parsed workflow — the job-level `uses: owner/repo/.github/workflows/x.yml@ref`
// that CollectActionRefs (which only reads step-level `uses:`) deliberately
// skips. Local calls (`./...`) are omitted: they aren't third-party. Kept a
// separate collector so callers that only want action refs (and the pin-audit /
// detection paths) are unaffected.
func CollectReusableWorkflowRefs(file string, jobs []JobNodeWithID) []ActionRef {
	var refs []ActionRef
	for _, jobWrap := range jobs {
		val := jobWrap.Node.Uses.Value
		if val == "" || strings.HasPrefix(val, "./") || strings.HasPrefix(val, ".github/") {
			continue
		}
		at := strings.SplitN(val, "@", 2)
		if len(at) != 2 {
			continue
		}
		// owner/repo/<path...> — need at least owner, repo, and one path segment.
		parts := strings.Split(at[0], "/")
		if len(parts) < 3 {
			continue
		}
		refs = append(refs, ActionRef{
			File:           file,
			Line:           jobWrap.Node.Uses.Line,
			Column:         jobWrap.Node.Uses.Column,
			Owner:          parts[0],
			Repo:           parts[1],
			Ref:            at[1],
			Raw:            val,
			VersionComment: strings.TrimSpace(strings.TrimLeft(jobWrap.Node.Uses.LineComment, "# ")),
			Kind:           RefKindReusableWorkflow,
			Path:           strings.Join(parts[2:], "/"),
		})
	}
	return refs
}

// CollectReusableWorkflowRefsFromBytes parses one GitHub workflow file's bytes
// and returns its remote reusable-workflow calls. GitLab files yield nothing.
// Mirror of CollectActionRefsFromBytes for the job-level surface.
func CollectReusableWorkflowRefsFromBytes(name string, content []byte) []ActionRef {
	if IsGitLabCIPath(name) {
		return nil
	}
	var workflow WorkflowNode
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil
	}
	if workflow.Jobs.Kind != yaml.MappingNode {
		return nil
	}
	var jobs []JobNodeWithID
	for i := 0; i+1 < len(workflow.Jobs.Content); i += 2 {
		keyNode := workflow.Jobs.Content[i]
		valNode := workflow.Jobs.Content[i+1]
		var job JobNode
		if err := valNode.Decode(&job); err == nil {
			jobs = append(jobs, JobNodeWithID{ID: keyNode.Value, Line: keyNode.Line, Column: keyNode.Column, Node: job})
		}
	}
	return CollectReusableWorkflowRefs(name, jobs)
}

// CollectActionRefsFromBytes parses one GitHub workflow file's bytes and returns
// its action references. GitLab files have no equivalent `uses:` surface and
// yield nothing. Used by the web scan pipeline, which holds file content in
// memory.
func CollectActionRefsFromBytes(name string, content []byte) []ActionRef {
	if IsGitLabCIPath(name) {
		return nil
	}
	var workflow WorkflowNode
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil
	}
	if workflow.Jobs.Kind != yaml.MappingNode {
		return nil
	}
	var jobs []JobNodeWithID
	for i := 0; i+1 < len(workflow.Jobs.Content); i += 2 {
		keyNode := workflow.Jobs.Content[i]
		valNode := workflow.Jobs.Content[i+1]
		var job JobNode
		if err := valNode.Decode(&job); err == nil {
			jobs = append(jobs, JobNodeWithID{ID: keyNode.Value, Line: keyNode.Line, Column: keyNode.Column, Node: job})
		}
	}
	return CollectActionRefs(name, &workflow, jobs)
}

// CollectActionRefsFromDir walks a repo's .github/workflows directory and
// returns every action reference across its workflow files. Used by the CLI's
// --audit-pins pass.
func CollectActionRefsFromDir(dirPath string) []ActionRef {
	var refs []ActionRef
	workflowsDir := filepath.Join(dirPath, ".github", "workflows")
	info, err := os.Stat(workflowsDir)
	if err != nil || !info.IsDir() {
		return refs
	}
	_ = filepath.Walk(workflowsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		refs = append(refs, CollectActionRefsFromBytes(path, content)...)
		return nil
	})
	return refs
}

// AuditActionPins runs the four online supply-chain audits over the collected
// references. Network results are memoized per repo/ref so a heavily-reused
// action (e.g. actions/checkout) is looked up once. Lookup errors are
// swallowed per-ref so a transient failure can't sink the whole pass; the
// affected audit simply produces no finding.
func AuditActionPins(ctx context.Context, refs []ActionRef, auditor PinAuditor) []Finding {
	var findings []Finding

	resolved := map[string]struct {
		sha   string
		found bool
		ok    bool // lookup succeeded
	}{}
	resolve := func(owner, repo, ref string) (string, bool, bool) {
		key := owner + "/" + repo + "@" + ref
		if v, ok := resolved[key]; ok {
			return v.sha, v.found, v.ok
		}
		sha, found, err := auditor.ResolveRef(ctx, owner, repo, ref)
		v := struct {
			sha   string
			found bool
			ok    bool
		}{sha, found, err == nil}
		resolved[key] = v
		return v.sha, v.found, v.ok
	}

	advisoryCache := map[string][]Advisory{}
	advisoriesFor := func(owner, repo string) []Advisory {
		key := owner + "/" + repo
		if v, ok := advisoryCache[key]; ok {
			return v
		}
		advs, err := auditor.Advisories(ctx, owner, repo)
		if err != nil {
			advs = nil
		}
		advisoryCache[key] = advs
		return advs
	}

	// archivedCache maps "owner/repo" → archived (only cached when ok).
	archivedCache := map[string]bool{}
	archivedFor := func(owner, repo string) (bool, bool) {
		key := owner + "/" + repo
		if v, ok := archivedCache[key]; ok {
			return v, true
		}
		archived, ok, err := auditor.RepoArchived(ctx, owner, repo)
		if err != nil || !ok {
			return false, false
		}
		archivedCache[key] = archived
		return archived, true
	}

	// tagSHAsCache maps "owner/repo" → set of tag commit SHAs (lowercased).
	tagSHAsCache := map[string]map[string]bool{}
	tagSHAsFor := func(owner, repo string) (map[string]bool, bool) {
		key := owner + "/" + repo
		if v, ok := tagSHAsCache[key]; ok {
			return v, true
		}
		shas, err := auditor.TagSHAs(ctx, owner, repo)
		if err != nil {
			return nil, false
		}
		set := make(map[string]bool, len(shas))
		for _, s := range shas {
			set[strings.ToLower(s)] = true
		}
		tagSHAsCache[key] = set
		return set, true
	}

	for _, r := range refs {
		isSHA := reSHA40.MatchString(r.Ref)

		if f := checkTyposquat(r); f != nil {
			findings = append(findings, *f)
		}

		// archived-action: the upstream repo is archived/unmaintained.
		if archived, ok := archivedFor(r.Owner, r.Repo); ok && archived {
			findings = append(findings, archivedFinding(r))
		}

		if isSHA {
			// impostor-commit: the pinned SHA isn't in the claimed repo.
			if _, found, ok := resolve(r.Owner, r.Repo, r.Ref); ok && !found {
				findings = append(findings, impostorFinding(r))
			}
			// ref-version-mismatch: the documented version resolves elsewhere.
			if v := versionFromComment(r.VersionComment); v != "" {
				if tagSHA, found, ok := resolve(r.Owner, r.Repo, v); ok && found && !strings.EqualFold(tagSHA, r.Ref) {
					findings = append(findings, refMismatchFinding(r, v, tagSHA))
				}
			}
			// stale-action-ref: pinned to a commit that is not any released tag.
			if tagSet, ok := tagSHAsFor(r.Owner, r.Repo); ok && len(tagSet) > 0 && !tagSet[strings.ToLower(r.Ref)] {
				findings = append(findings, staleRefFinding(r))
			}
		} else {
			// ref-confusion: a non-SHA ref that exists as both a branch and a tag.
			if isBranch, isTag, err := auditor.RefKinds(ctx, r.Owner, r.Repo, r.Ref); err == nil && isBranch && isTag {
				findings = append(findings, refConfusionFinding(r))
			}
		}

		// known-vulnerable-action: match the pinned (or commented) version
		// against published advisory ranges.
		version := r.Ref
		if isSHA {
			version = versionFromComment(r.VersionComment)
		}
		if version != "" {
			for _, a := range advisoriesFor(r.Owner, r.Repo) {
				if versionInRange(version, a.VulnerableRange) {
					findings = append(findings, knownVulnFinding(r, a))
				}
			}
		}
	}

	return StampConfidence(findings)
}

// versionFromComment pulls a version token out of a uses: line comment.
func versionFromComment(comment string) string {
	if comment == "" {
		return ""
	}
	return reVersionToken.FindString(comment)
}

// normalizeSemver coerces an action version (v1, 1.2, v1.2.3) into a canonical
// semver string ("vX.Y.Z"), or "" if it isn't a recognizable version.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return semver.Canonical(v)
}

// versionInRange reports whether version satisfies a GHSA vulnerable_version_range
// like "< 1.2.3", "<= 1.2.3", ">= 1.0.0, < 1.2.3", or "= 1.0.0". Unparseable
// constraints are treated as non-matching (conservative — avoid false positives).
func versionInRange(version, rangeExpr string) bool {
	v := normalizeSemver(version)
	if v == "" || strings.TrimSpace(rangeExpr) == "" {
		return false
	}
	for _, part := range strings.Split(rangeExpr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op := "="
		rest := part
		for _, candidate := range []string{"<=", ">=", "<", ">", "="} {
			if strings.HasPrefix(part, candidate) {
				op = candidate
				rest = strings.TrimSpace(part[len(candidate):])
				break
			}
		}
		bound := normalizeSemver(rest)
		if bound == "" {
			return false
		}
		cmp := semver.Compare(v, bound)
		ok := false
		switch op {
		case "<":
			ok = cmp < 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case ">=":
			ok = cmp >= 0
		case "=":
			ok = cmp == 0
		}
		if !ok {
			return false
		}
	}
	return true
}

func impostorFinding(r ActionRef) Finding {
	return Finding{
		File:     r.File,
		Line:     r.Line,
		Column:   r.Column,
		Severity: SeverityHigh,
		Category: "CICD-SEC-3",
		RuleID:   RuleImpostorCommit,
		Title:    "Impostor commit pin",
		Description: fmt.Sprintf(
			"Action %q is pinned to commit %s, but that commit does not exist in %s/%s. "+
				"The SHA may belong to a fork or have been force-removed — pinning to it runs code the upstream repository never published.",
			r.Raw, r.Ref, r.Owner, r.Repo),
		Recommendation: "Re-pin to a commit SHA that is reachable from a real tag or branch in the upstream repository, and verify the action's source before trusting it.",
	}
}

func refMismatchFinding(r ActionRef, version, tagSHA string) Finding {
	return Finding{
		File:     r.File,
		Line:     r.Line,
		Column:   r.Column,
		Severity: SeverityMedium,
		Category: "CICD-SEC-3",
		RuleID:   RuleRefVersionMismatch,
		Title:    "Pinned SHA does not match its version comment",
		Description: fmt.Sprintf(
			"Action %q is pinned to %s with a comment naming %q, but %s/%s's %s tag points to %s. "+
				"The comment is misleading — reviewers think they're getting %s while a different commit runs.",
			r.Raw, r.Ref, version, r.Owner, r.Repo, version, tagSHA, version),
		Recommendation: "Update the pinned SHA to the one the tag actually resolves to, or correct the version comment so it matches the pinned commit.",
	}
}

func archivedFinding(r ActionRef) Finding {
	return Finding{
		File:     r.File,
		Line:     r.Line,
		Column:   r.Column,
		Severity: SeverityHigh,
		Category: "CICD-SEC-3",
		RuleID:   RuleArchivedAction,
		Title:    "Action's upstream repository is archived",
		Description: fmt.Sprintf(
			"Action %q comes from %s/%s, which GitHub reports as archived (read-only). "+
				"Archived actions receive no maintenance or security fixes, so any vulnerability in it is permanent.",
			r.Raw, r.Owner, r.Repo),
		Recommendation: "Migrate to a maintained fork or an actively-supported alternative, and re-pin it to a commit SHA.",
	}
}

func staleRefFinding(r ActionRef) Finding {
	return Finding{
		File:     r.File,
		Line:     r.Line,
		Column:   r.Column,
		Severity: SeverityMedium,
		Category: "CICD-SEC-3",
		RuleID:   RuleStaleActionRef,
		Title:    "Pinned SHA is not any released tag",
		Description: fmt.Sprintf(
			"Action %q is pinned to commit %s, which is not the tip of any tag in %s/%s. "+
				"You are running unreleased or arbitrary code rather than a published, reviewable release.",
			r.Raw, r.Ref, r.Owner, r.Repo),
		Recommendation: "Pin to a commit SHA that corresponds to a published release tag, and record the tag in a trailing comment (e.g. @<sha> # v1.2.3).",
	}
}

func refConfusionFinding(r ActionRef) Finding {
	return Finding{
		File:     r.File,
		Line:     r.Line,
		Column:   r.Column,
		Severity: SeverityHigh,
		Category: "CICD-SEC-3",
		RuleID:   RuleRefConfusion,
		Title:    "Action ref exists as both a branch and a tag",
		Description: fmt.Sprintf(
			"Action %q references %q, which exists in %s/%s as BOTH a branch and a tag. "+
				"GitHub's ref-resolution order makes this ambiguous, and an attacker who can push the branch may shadow the intended tag.",
			r.Raw, r.Ref, r.Owner, r.Repo),
		Recommendation: "Pin the action to a full commit SHA so resolution is unambiguous, or reference a ref name that is not overloaded.",
	}
}

func knownVulnFinding(r ActionRef, a Advisory) Finding {
	patched := ""
	if a.FirstPatched != "" {
		patched = fmt.Sprintf(" Fixed in %s.", a.FirstPatched)
	}
	return Finding{
		File:     r.File,
		Line:     r.Line,
		Column:   r.Column,
		Severity: SeverityHigh,
		Category: "CICD-SEC-3",
		RuleID:   RuleKnownVulnerableAction,
		Title:    "Known-vulnerable action version",
		Description: fmt.Sprintf(
			"Action %q resolves to a version in the vulnerable range %q of advisory %s: %s.%s",
			r.Raw, a.VulnerableRange, a.GHSAID, a.Summary, patched),
		Recommendation: "Upgrade to a patched version of the action (and re-pin to its commit SHA). See the linked GHSA advisory for details.",
	}
}
