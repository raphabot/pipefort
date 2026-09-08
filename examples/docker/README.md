# Running Pipefort in Docker

- **Requires:** Docker, and a checkout of this repository (the image is built from source;
  there is no published image today)
- **Env vars:** none for form (a); `INPUT_*` for form (b)
- **Result:** findings printed to stdout; exit code 1 when a finding is at or above the
  `fail-on` threshold

## Build

```bash
docker build -f Dockerfile.action -t pipefort .
```

## Run

`Dockerfile.action` exists to back the **GitHub Action**, so its `ENTRYPOINT` is the action
wrapper `action/entrypoint.sh` — not the `pipefort` binary. The wrapper builds its own
argument list from `INPUT_*` environment variables and **discards anything you pass on the
command line**. Pick one of these two forms:

```bash
# (a) Bypass the wrapper and drive the CLI directly — recommended for ad-hoc use.
docker run --rm -v "$PWD:/repo" --entrypoint pipefort pipefort -p /repo

# Any CLI flag works in form (a):
docker run --rm -v "$PWD:/repo" --entrypoint pipefort pipefort -p /repo -o json
docker run --rm -v "$PWD:/repo" --entrypoint pipefort pipefort -p /repo --fail-on HIGH
```

```bash
# (b) Drive the wrapper through its inputs — mirrors exactly what the Action does.
docker run --rm -v "$PWD:/repo" \
  -e INPUT_PATH=/repo \
  -e INPUT_OUTPUT=console \
  -e INPUT_RULESET=all \
  -e INPUT_FAIL_ON=MEDIUM \
  pipefort
```

## What does not work

```bash
# WRONG — the wrapper discards "-p /repo".
docker run --rm -v "$PWD:/repo" pipefort -p /repo
```

With the argument gone, `INPUT_PATH` falls back to its default of `.`, and because the
image sets no `WORKDIR`, `.` is the **container root** — not your mount. What you
actually get:

```text
$ docker run --rm -v "$PWD:/repo" pipefort -p /repo
Error: scan failed: lstat proc/7/fd/4: no such file or directory
Usage:
  pipefort [flags]
...
$ echo $?
1
```

Empty stdout, exit 1, and your repository never read.

## Getting SARIF out of the container

Mount a writable directory and redirect, rather than relying on the wrapper's file write:

```bash
docker run --rm -v "$PWD:/repo" --entrypoint pipefort pipefort \
  -p /repo -o sarif > pipefort.sarif
```

## Notes

- The image installs `git` (2.45.x) and `ca-certificates`, so `--git` clones work inside it.
- There is no `WORKDIR` in the final stage, so relative paths resolve against `/`. Always use
  the absolute mount path (`/repo`).
- `pipefort --version` reports `dev` inside this image. That is correct: `Dockerfile.action`
  compiles from the checked-out source without GoReleaser's `-X main.version` stamp, so the
  binary is a source build rather than a tagged release.
- To keep the scan fully offline, pass `--offline` in form (a), or set `INPUT_GITHUB_TOKEN=''`
  in form (b).
