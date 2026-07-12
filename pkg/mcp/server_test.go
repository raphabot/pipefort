package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect wires an in-memory client to the Pipefort MCP server.
func connect(t *testing.T) (*mcpsdk.ClientSession, context.Context) {
	t.Helper()
	ctx := context.Background()
	server := NewServer()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test", Version: "0"}, nil)
	st, ct := mcpsdk.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, ctx
}

// resultText concatenates the text content of a tool result.
func resultText(t *testing.T, res *mcpsdk.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcpsdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestMCPListTools(t *testing.T) {
	cs, ctx := connect(t)
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, want := range []string{"scan_workflow", "scan_directory", "explain_rule"} {
		if !got[want] {
			t.Errorf("missing tool %q (have %v)", want, got)
		}
	}
}

func TestMCPScanWorkflow(t *testing.T) {
	cs, ctx := connect(t)
	wf := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`
	res, err := cs.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      "scan_workflow",
		Arguments: map[string]any{"content": wf},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", resultText(t, res))
	}
	var out struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &out); err != nil {
		t.Fatalf("decode result: %v (%s)", err, resultText(t, res))
	}
	// The untrusted-interpolation-in-run should surface a PPE injection finding.
	var sawInjection bool
	for _, f := range out.Findings {
		if f.RuleID == "cicd-sec-4-ppe-shell-injection" {
			sawInjection = true
		}
	}
	if !sawInjection {
		t.Errorf("expected a shell-injection finding, got %s", resultText(t, res))
	}
}

func TestMCPExplainRule(t *testing.T) {
	cs, ctx := connect(t)
	res, err := cs.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      "explain_rule",
		Arguments: map[string]any{"rule_id": "cicd-sec-5-missing-permissions"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", resultText(t, res))
	}
	if !strings.Contains(resultText(t, res), "Missing permissions") {
		t.Errorf("explain_rule missing expected title: %s", resultText(t, res))
	}

	// Unknown rule → IsError.
	bad, err := cs.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      "explain_rule",
		Arguments: map[string]any{"rule_id": "nope"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !bad.IsError {
		t.Error("expected IsError for an unknown rule id")
	}
}
