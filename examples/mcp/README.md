# Pipefort as an MCP server

Let an AI coding assistant scan CI workflow YAML **while it writes it** — catching an
injection sink or an unpinned action before the file is ever committed.

- **Requires:** `pipefort` on `PATH` (see [installation](https://pipefort.com/docs/cli/installation))
- **Env vars:** none
- **Network:** none — the server is read-only and offline
- **Transport:** stdio

## Register

### Claude Code

```bash
claude mcp add pipefort -- pipefort mcp
```

### Any client that takes a JSON server config

```json
{
  "mcpServers": {
    "pipefort": {
      "command": "pipefort",
      "args": ["mcp"]
    }
  }
}
```

Use an absolute path (`/usr/local/bin/pipefort`, or the output of `which pipefort`) if your
client does not inherit your shell `PATH`.

## Verify

```bash
pipefort mcp     # blocks, speaking MCP over stdin/stdout — Ctrl-C to stop
```

A silent block is success. The server reports its implementation as `pipefort` with the
binary's real version (`pipefort --version`).

## Tools

| Tool | Required | Optional | Returns |
|---|---|---|---|
| `scan_workflow` | `content` — the raw YAML | `filename`, `ruleset`, `persona`, `min_confidence` | `{"findings": [...]}` |
| `scan_directory` | `path` — a local directory | `ruleset`, `persona`, `min_confidence` | `{"findings": [...], "toxic_combinations": [...]}` |
| `explain_rule` | `rule_id` — e.g. `cicd-sec-4-ppe-shell-injection` | — | the rule's catalog entry: title, severity, confidence, description, docs URL |

Optional-field defaults: `ruleset` = `all`, `persona` = `regular`, `min_confidence` = `LOW`
(keeps everything). `filename` defaults to `.github/workflows/workflow.yml`.

**Platform dispatch is by filename, not content.** Pass `filename: ".gitlab-ci.yml"` to scan
GitLab CI; anything else is treated as a GitHub Actions workflow.

## Prompts that work well

- "Scan this workflow with pipefort before I commit it."
- "pipefort flagged `cicd-sec-4-ppe-shell-injection` — explain the rule and rewrite the step
  so it passes."
- "Run `scan_directory` on this repo and show me only the toxic combinations."
