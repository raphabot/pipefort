# Architecture decision records

Short, durable records of decisions that constrain future work. They are
numbered and never deleted: supersede a record with a new one, and mark the
old one `Superseded by NNNN`.

Format: **Context → Decision → Consequences**, under a page.

| # | Decision | Status |
|---|---|---|
| [0001](0001-offline-first-no-telemetry.md) | The CLI is offline-first and never phones home | Accepted |
| [0002](0002-package-layering-no-pgx.md) | Leaf scanner package; no datastore dependency in the CLI | Accepted |
| [0003](0003-rule-docs-live-in-cloud.md) | Rule docs live in the private cloud repo | Accepted |
