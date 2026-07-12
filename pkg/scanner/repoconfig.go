package scanner

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RepoConfig is an in-repo `.pipefort.yml` — the CLI-friendly counterpart to
// the web app's DB-backed rule settings. It lets a repository ship its own
// scan preferences and per-rule suppressions alongside its code, so a `pipefort`
// run needs no external state. zizmor's `zizmor.yml` is the direct analog.
//
// Every field is optional. The zero value applies nothing.
type RepoConfig struct {
	// Ruleset / MinConfidence / Persona are defaults for the corresponding CLI
	// flags; an explicit flag always wins (see LoadRepoConfig callers).
	Ruleset       string `yaml:"ruleset"`
	MinConfidence string `yaml:"min-confidence"`
	Persona       string `yaml:"persona"`

	// Rules holds per-rule overrides keyed by RuleID.
	Rules map[string]RuleOverride `yaml:"rules"`

	// ForbiddenUses drives the cicd-sec-5-forbidden-uses rule (allow XOR deny
	// list of action references). Consumed by that check; nil = rule silent.
	ForbiddenUses *ForbiddenUses `yaml:"forbidden-uses"`
}

// RuleOverride is a single rule's configuration.
type RuleOverride struct {
	// Enabled, when non-nil and false, disables the rule entirely. A repo
	// config can only *disable* a rule, never re-enable one an org policy
	// turned off (enforced by the web layer, not here).
	Enabled *bool `yaml:"enabled"`
	// Severity, when set, rewrites the finding severity (HIGH/MEDIUM/LOW/INFO).
	Severity string `yaml:"severity"`
	// Ignore suppresses findings of this rule at specific files/lines.
	Ignore []IgnoreEntry `yaml:"ignore"`
}

// IgnoreEntry suppresses a rule at a file (glob, repo-relative) and, optionally,
// specific 1-based line numbers. An empty Lines slice suppresses the whole file.
type IgnoreEntry struct {
	File  string `yaml:"file"`
	Lines []int  `yaml:"lines"`
}

// ForbiddenUses is an allow/deny policy for action references. Exactly one of
// Allow (only these are permitted) or Deny (these are forbidden) should be set;
// when both are present, Allow takes precedence.
type ForbiddenUses struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// repoConfigNames are the candidate filenames, in precedence order.
var repoConfigNames = []string{
	".pipefort.yml",
	".pipefort.yaml",
	".github/pipefort.yml",
	".github/pipefort.yaml",
}

// ConfigFileNames returns the candidate config filenames in precedence order,
// so the web API can fetch them over the provider's contents API.
func ConfigFileNames() []string {
	return append([]string(nil), repoConfigNames...)
}

// LoadRepoConfig looks for a config file under dir (in repoConfigNames order)
// and parses it. Returns (nil, "", nil) when none is present. The returned
// string is the relative path found, for user-facing messaging.
func LoadRepoConfig(dir string) (*RepoConfig, string, error) {
	for _, name := range repoConfigNames {
		p := filepath.Join(dir, filepath.FromSlash(name))
		data, err := os.ReadFile(p)
		if err != nil {
			continue // not found / unreadable — try the next candidate
		}
		cfg, err := ParseRepoConfig(data)
		if err != nil {
			return nil, name, fmt.Errorf("parse %s: %w", name, err)
		}
		return cfg, name, nil
	}
	return nil, "", nil
}

// ParseRepoConfig unmarshals config bytes and validates enum-ish fields so a
// typo (e.g. persona: auditer) is surfaced instead of silently ignored.
func ParseRepoConfig(data []byte) (*RepoConfig, error) {
	var cfg RepoConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Persona != "" {
		switch Persona(strings.ToLower(cfg.Persona)) {
		case PersonaRegular, PersonaPedantic, PersonaAuditor:
		default:
			return nil, fmt.Errorf("invalid persona %q (want regular|pedantic|auditor)", cfg.Persona)
		}
	}
	if cfg.MinConfidence != "" {
		switch Confidence(strings.ToUpper(cfg.MinConfidence)) {
		case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		default:
			return nil, fmt.Errorf("invalid min-confidence %q (want HIGH|MEDIUM|LOW)", cfg.MinConfidence)
		}
	}
	for id, ov := range cfg.Rules {
		if ov.Severity != "" {
			switch Severity(strings.ToUpper(ov.Severity)) {
			case SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
			default:
				return nil, fmt.Errorf("rule %q: invalid severity %q", id, ov.Severity)
			}
		}
	}
	return &cfg, nil
}

// DisabledRuleIDs returns the set of rules the config turns off. Used by the web
// layer to union config-disabled rules into the DB-backed disabled set (a repo
// config may further-restrict, never re-enable).
func (c *RepoConfig) DisabledRuleIDs() map[RuleID]bool {
	out := map[RuleID]bool{}
	if c == nil {
		return out
	}
	for id, ov := range c.Rules {
		if ov.Enabled != nil && !*ov.Enabled {
			out[RuleID(id)] = true
		}
	}
	return out
}

// ApplyRepoConfig applies a repo config to a finished finding list as a pure
// transform: drop disabled rules, drop file/line-matched ignores, and rewrite
// severities. SYSTEM findings (empty RuleID) always pass. A nil config is a
// no-op. This runs after the file paths are normalized to repo-relative so the
// glob matching in IgnoreEntry.File works.
func ApplyRepoConfig(findings []Finding, cfg *RepoConfig) []Finding {
	if cfg == nil || len(cfg.Rules) == 0 {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == "" {
			out = append(out, f)
			continue
		}
		ov, ok := cfg.Rules[string(f.RuleID)]
		if !ok {
			out = append(out, f)
			continue
		}
		if ov.Enabled != nil && !*ov.Enabled {
			continue // rule disabled
		}
		if ignoredByConfig(f, ov.Ignore) {
			continue
		}
		if ov.Severity != "" {
			f.Severity = Severity(strings.ToUpper(ov.Severity))
		}
		out = append(out, f)
	}
	return out
}

// ignoredByConfig reports whether a finding is covered by any ignore entry.
func ignoredByConfig(f Finding, entries []IgnoreEntry) bool {
	for _, e := range entries {
		if e.File != "" && !matchFileGlob(e.File, f.File) {
			continue
		}
		if len(e.Lines) == 0 {
			return true // whole-file ignore
		}
		for _, ln := range e.Lines {
			if ln == f.Line {
				return true
			}
		}
	}
	return false
}

// matchFileGlob matches a repo-relative glob against a finding's file path,
// tolerating absolute / temp-clone prefixes by also matching the pattern
// against the trailing path segments.
func matchFileGlob(pattern, file string) bool {
	pattern = filepath.ToSlash(pattern)
	file = filepath.ToSlash(file)
	if ok, _ := path.Match(pattern, file); ok {
		return true
	}
	pSegs := strings.Count(pattern, "/") + 1
	segs := strings.Split(file, "/")
	if len(segs) > pSegs {
		tail := strings.Join(segs[len(segs)-pSegs:], "/")
		if ok, _ := path.Match(pattern, tail); ok {
			return true
		}
	}
	return false
}
