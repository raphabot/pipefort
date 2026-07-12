package vcs

import (
	"context"
	"sort"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// OrgScanner scans every repository owned by a GitHub org or user by fetching
// workflow YAML over the API (no cloning) and running the same in-memory
// scanner.ScanBytes the web app uses. It is the CLI counterpart to the web
// app's per-repo scan, aggregated across an owner — poutine's analyze_org.
type OrgScanner struct {
	Client *GitHubClient
}

// NewOrgScanner builds an org scanner over a bare (App-less) GitHub client.
func NewOrgScanner() *OrgScanner {
	return &OrgScanner{Client: NewBareGitHubClient()}
}

// OrgScanOptions tunes an org scan. Zero values are sensible: ruleset "all",
// persona regular, no min-confidence, online audits off, concurrency 4.
type OrgScanOptions struct {
	Ruleset       string
	Persona       scanner.Persona
	MinConfidence scanner.Confidence
	Online        bool // run the online pin audits (needs network)
	Concurrency   int
}

// RepoScanResult is one repository's outcome. Err is set (and Findings nil)
// when that repo could not be scanned; the org scan continues regardless.
type RepoScanResult struct {
	FullName string
	Findings []scanner.Finding
	Combos   []scanner.ToxicCombo
	Err      error
}

// OrgScanResult aggregates the per-repo results for one owner.
type OrgScanResult struct {
	Owner string
	Repos []RepoScanResult
}

// Scan enumerates the owner's repositories and scans each with bounded
// concurrency. Per-repo failures are captured in the result, never fatal —
// only listing the owner's repos can fail the whole call.
func (o *OrgScanner) Scan(ctx context.Context, token, owner string, opts OrgScanOptions) (*OrgScanResult, error) {
	repos, err := o.Client.ListOwnerRepos(ctx, token, owner)
	if err != nil {
		return nil, err
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 4
	}

	results := make([]RepoScanResult, len(repos))
	sem := make(chan struct{}, conc)
	g, gctx := errgroup.WithContext(ctx)
	for i := range repos {
		i, repo := i, repos[i]
		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = o.scanOne(gctx, token, repo, opts)
			return nil
		})
	}
	_ = g.Wait() // per-repo errors are in results; the group never returns one

	// Deterministic order (repos come back API-ordered, but scans race).
	sort.Slice(results, func(a, b int) bool { return results[a].FullName < results[b].FullName })
	return &OrgScanResult{Owner: owner, Repos: results}, nil
}

// scanOne fetches and scans a single repository. Finding file paths are
// prefixed with the repo full name so aggregated output stays unambiguous.
func (o *OrgScanner) scanOne(ctx context.Context, token string, repo Repo, opts OrgScanOptions) RepoScanResult {
	res := RepoScanResult{FullName: repo.FullName}

	files, err := o.Client.FetchWorkflows(ctx, token, repo.Owner.Login, repo.Name, "")
	if err != nil {
		res.Err = err
		return res
	}

	var repoCfg *scanner.RepoConfig
	if cfgBytes, cfgErr := o.Client.FetchRepoConfig(ctx, token, repo.Owner.Login, repo.Name, ""); cfgErr == nil && len(cfgBytes) > 0 {
		if parsed, parseErr := scanner.ParseRepoConfig(cfgBytes); parseErr == nil {
			repoCfg = parsed
		}
	}

	var findings []scanner.Finding
	var actionRefs []scanner.ActionRef
	for _, f := range files {
		ff, scanErr := scanner.ScanBytes(f.Path, f.Content)
		if scanErr != nil {
			continue // skip unparseable files (mirrors ScanDir)
		}
		findings = append(findings, ff...)
		actionRefs = append(actionRefs, scanner.CollectActionRefsFromBytes(f.Path, f.Content)...)
	}

	if opts.Online && len(actionRefs) > 0 {
		auditor := scanner.NewGitHubPinAuditor(token)
		findings = append(findings, scanner.AuditActionPins(ctx, actionRefs, auditor)...)
	}
	if repoCfg != nil && repoCfg.ForbiddenUses != nil {
		findings = append(findings, scanner.CheckForbiddenUses(actionRefs, repoCfg.ForbiddenUses)...)
	}

	// Config transform + ruleset/persona/confidence filters, mirroring the CLI.
	findings = scanner.ApplyRepoConfig(findings, repoCfg)
	findings = scanner.FilterFindings(findings, opts.Ruleset)
	findings = scanner.FilterByPersona(findings, opts.Persona)
	findings = scanner.FilterByConfidence(findings, opts.MinConfidence)

	// Prefix each finding's file with the repo so aggregated reports are clear.
	for i := range findings {
		if findings[i].File != "" && findings[i].File != scanner.SettingsFile {
			findings[i].File = repo.FullName + "/" + findings[i].File
		}
	}

	res.Findings = findings
	res.Combos = scanner.DetectToxicCombinations(findings)
	return res
}

// Flatten returns every repo's findings and combos as two aggregated slices,
// for feeding the existing reporters. Failed repos contribute nothing.
func (r *OrgScanResult) Flatten() ([]scanner.Finding, []scanner.ToxicCombo) {
	var findings []scanner.Finding
	var combos []scanner.ToxicCombo
	for _, rr := range r.Repos {
		findings = append(findings, rr.Findings...)
		combos = append(combos, rr.Combos...)
	}
	return findings, combos
}

// Errors returns the repos that failed to scan, as "full_name: message".
func (r *OrgScanResult) Errors() []string {
	var out []string
	for _, rr := range r.Repos {
		if rr.Err != nil {
			out = append(out, rr.FullName+": "+rr.Err.Error())
		}
	}
	return out
}

// SeverityLine returns a per-repo one-line summary ("owner/repo  H:2 M:1 L:0"),
// skipping clean repos, for the console aggregate table.
func (r *OrgScanResult) SeverityLines() []string {
	var out []string
	for _, rr := range r.Repos {
		if rr.Err != nil {
			out = append(out, rr.FullName+"  (scan failed)")
			continue
		}
		var h, m, l, info int
		for _, f := range rr.Findings {
			switch f.Severity {
			case scanner.SeverityHigh:
				h++
			case scanner.SeverityMedium:
				m++
			case scanner.SeverityLow:
				l++
			default:
				info++
			}
		}
		if h+m+l+info == 0 {
			continue // omit clean repos from the table
		}
		out = append(out, rr.FullName+"  "+strings.TrimSpace(
			joinCounts(h, m, l, info)))
	}
	return out
}

func joinCounts(h, m, l, info int) string {
	parts := []string{}
	if h > 0 {
		parts = append(parts, "H:"+itoa(h))
	}
	if m > 0 {
		parts = append(parts, "M:"+itoa(m))
	}
	if l > 0 {
		parts = append(parts, "L:"+itoa(l))
	}
	if info > 0 {
		parts = append(parts, "I:"+itoa(info))
	}
	return strings.Join(parts, " ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
