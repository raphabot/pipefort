// Package mcp exposes Pipefort's scanner over the Model Context Protocol so AI
// coding assistants (Claude Code, Gemini CLI, …) can scan CI workflows as they
// write them. It wraps the same scanner.ScanBytes / ScanDir the CLI and web app
// use, over the official Go MCP SDK's stdio transport.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/raphabot/pipefort/pkg/scanner"
)

// Version is stamped into the MCP server's implementation info.
const Version = "0.1.0"

// NewServer builds the Pipefort MCP server with its tool set registered.
func NewServer() *mcpsdk.Server {
	s := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "pipefort",
		Title:   "Pipefort CI/CD security scanner",
		Version: Version,
	}, nil)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_workflow",
		Description: "Scan a single CI workflow file's contents for OWASP CI/CD Top 10 and supply-chain risks. Pass the file's `content`; set `filename` to `.gitlab-ci.yml` to scan GitLab CI (defaults to GitHub Actions). Returns findings as JSON.",
	}, scanWorkflow)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "scan_directory",
		Description: "Scan a local directory's GitHub Actions (.github/workflows/*) and GitLab CI (.gitlab-ci.yml) files. Returns findings plus detected toxic combinations ('Attacker Mind') as JSON.",
	}, scanDirectory)

	mcpsdk.AddTool(s, &mcpsdk.Tool{
		Name:        "explain_rule",
		Description: "Return the catalog entry (title, severity, confidence, description, docs URL) for a Pipefort rule ID, e.g. 'cicd-sec-4-ppe-shell-injection'.",
	}, explainRule)

	return s
}

// Run serves the MCP server over stdio until the context is cancelled or the
// client disconnects.
func Run(ctx context.Context) error {
	return NewServer().Run(ctx, &mcpsdk.StdioTransport{})
}

// --- tool inputs ------------------------------------------------------------

type scanWorkflowInput struct {
	Content       string `json:"content" jsonschema:"the raw YAML content of the workflow file"`
	Filename      string `json:"filename,omitempty" jsonschema:"the file's path/name; controls GitHub vs GitLab dispatch (default GitHub Actions)"`
	Ruleset       string `json:"ruleset,omitempty" jsonschema:"all|owasp|slsa|slsa-build-l2|... (default all)"`
	Persona       string `json:"persona,omitempty" jsonschema:"regular|pedantic|auditor (default regular)"`
	MinConfidence string `json:"min_confidence,omitempty" jsonschema:"HIGH|MEDIUM|LOW (default LOW, keep everything)"`
}

type scanDirectoryInput struct {
	Path          string `json:"path" jsonschema:"the local directory to scan"`
	Ruleset       string `json:"ruleset,omitempty"`
	Persona       string `json:"persona,omitempty"`
	MinConfidence string `json:"min_confidence,omitempty"`
}

type explainRuleInput struct {
	RuleID string `json:"rule_id" jsonschema:"the Pipefort rule ID to explain"`
}

// --- handlers ---------------------------------------------------------------

func scanWorkflow(_ context.Context, _ *mcpsdk.CallToolRequest, in scanWorkflowInput) (*mcpsdk.CallToolResult, any, error) {
	name := in.Filename
	if name == "" {
		name = ".github/workflows/workflow.yml"
	}
	findings, err := scanner.ScanBytes(name, []byte(in.Content))
	if err != nil {
		return errorResult(err), nil, nil
	}
	findings = applyFilters(findings, in.Ruleset, in.Persona, in.MinConfidence)
	return jsonResult(map[string]any{"findings": nonNil(findings)})
}

func scanDirectory(_ context.Context, _ *mcpsdk.CallToolRequest, in scanDirectoryInput) (*mcpsdk.CallToolResult, any, error) {
	if strings.TrimSpace(in.Path) == "" {
		return errorResult(fmt.Errorf("path is required")), nil, nil
	}
	findings, err := scanner.ScanDir(in.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	findings = applyFilters(findings, in.Ruleset, in.Persona, in.MinConfidence)
	combos := scanner.DetectToxicCombinations(findings)
	return jsonResult(map[string]any{
		"findings":           nonNil(findings),
		"toxic_combinations": combos,
	})
}

func explainRule(_ context.Context, _ *mcpsdk.CallToolRequest, in explainRuleInput) (*mcpsdk.CallToolResult, any, error) {
	spec, ok := scanner.RuleByID()[scanner.RuleID(strings.TrimSpace(in.RuleID))]
	if !ok {
		return errorResult(fmt.Errorf("unknown rule id %q", in.RuleID)), nil, nil
	}
	return jsonResult(spec)
}

// --- helpers ----------------------------------------------------------------

// applyFilters mirrors the CLI's post-scan filtering. Empty values use the
// permissive defaults (ruleset "all", persona regular, no confidence floor).
func applyFilters(findings []scanner.Finding, ruleset, persona, minConf string) []scanner.Finding {
	rs := ruleset
	if rs == "" {
		rs = "all"
	}
	findings = scanner.FilterFindings(findings, rs)
	findings = scanner.FilterByPersona(findings, scanner.Persona(strings.ToLower(strings.TrimSpace(persona))))
	findings = scanner.FilterByConfidence(findings, scanner.Confidence(strings.ToUpper(strings.TrimSpace(minConf))))
	return findings
}

func nonNil(f []scanner.Finding) []scanner.Finding {
	if f == nil {
		return []scanner.Finding{}
	}
	return f
}

func jsonResult(v any) (*mcpsdk.CallToolResult, any, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: string(b)}},
	}, nil, nil
}

func errorResult(err error) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{
		IsError: true,
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: err.Error()}},
	}
}
