# Security Policy

## Supported versions

Pipefort is released from the `main` branch and versioned with Git tags.
Security fixes are made against the latest release; please upgrade to the most
recent tagged version before reporting an issue.

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ (upgrade to latest) |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

The primary channel is **GitHub's private vulnerability reporting** (Security
Advisories) on this repository:

1. Go to the [Security tab](https://github.com/raphabot/pipefort/security).
2. Click **Report a vulnerability** to open a private advisory.

This creates a private thread with the maintainers. Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal workflow/config that triggers it), and
- any suggested remediation.

> A dedicated security contact email may be added here later; until then, the
> GitHub private advisory flow above is the way to reach the maintainers.

We aim to acknowledge reports promptly and will keep you updated as we
investigate and prepare a fix.

## Disclosure and the hosted service

Pipefort's scan **engine** is open source and lives here. Vulnerabilities in the
engine are disclosed and fixed **in the open** in this repository: we publish a
GitHub Security Advisory (GHSA), release a patched, tagged version, and credit
the reporter.

The hosted Pipefort service (a separate private codebase) depends on this
module. After a security tag is published here, the hosted service bumps its
pinned version and deploys the fix. This means an engine advisory may be visible
here before the hosted service has finished rolling out the update.
