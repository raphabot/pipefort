# Pipefort examples

Copy-pasteable recipes for the highest-value ways to run Pipefort. Every file states its
required dependencies, environment variables, and expected result at the top.

Nothing here is scanned by Pipefort's own self-scan: `ScanDir` only walks
`.github/workflows/`, a root `.gitlab-ci.yml`, and `.gitlab-ci/`. The config sample is
deliberately named `pipefort.yml`, not `.pipefort.yml`, so it can never be picked up as this
repository's own configuration.

| Recipe | Use it when |
|---|---|
| [`github-actions/sarif-upload.yml`](./github-actions/sarif-upload.yml) | You want findings in the GitHub Security tab. The canonical setup. |
| [`github-actions/cli-binary.yml`](./github-actions/cli-binary.yml) | You want a faster job than the Docker action, or PR-only diffing. |
| [`gitlab-ci/.gitlab-ci.yml`](./gitlab-ci/.gitlab-ci.yml) | You run GitLab CI. |
| [`config/pipefort.yml`](./config/pipefort.yml) | You need per-repo rule tuning, suppressions, or an action allow/deny policy. |
| [`config/inline-ignores.yml`](./config/inline-ignores.yml) | You want to suppress one finding where it sits, without a config file. |
| [`mcp/README.md`](./mcp/README.md) | You want an AI assistant to scan workflows as it writes them. |
| [`docker/README.md`](./docker/README.md) | You want to run Pipefort from a container. |

## The shortest possible start

No dependencies beyond the binary, no environment variables, no network:

```bash
curl -fsSL https://pipefort.com/install.sh | sh
pipefort -p .
```

Exit code `0` means nothing at or above `MEDIUM` was found; `1` means something was (or the
scan errored). See [`../AGENTS.md`](../AGENTS.md) for the full contract.
