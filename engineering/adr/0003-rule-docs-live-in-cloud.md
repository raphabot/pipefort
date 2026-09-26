# 0003 — Rule docs live in the private cloud repo

**Status:** Accepted (recorded retroactively, 2026-09)

## Context
The public docs site (Mintlify) is built from `pipefort-cloud/docs/`, next to the
SaaS features it also documents.

## Decision
A new rule's `docs/rules/<id>.mdx` page, its `rules/overview.mdx` entry and its
`docs.json` navigation entry land in the pipefort-cloud pin-bump PR, not here.
The catalog's `DocURL` points at that page.

## Consequences
- Every rule PR here names its companion cloud PR in the description.
- A rule is invisible in the web app until this module is tagged and the cloud
  pin is bumped.
