# Contributing to Daimon

Daimon is source-distributed and has not made a supported production release.
Read `docs/operating-rigor.md`, `docs/roadmap.md`, `docs/traceability.md`, and
`SECURITY.md` before changing behavior or claims.

Run the complete offline workspace and peer-profile gate before submitting
changes:

```sh
make check
```

The gates require the exact sibling revisions recorded in
`release/github-source.json`, local subprocess and Unix-socket support, macOS
Seatbelt for its selected isolation evidence, and `ripgrep` (`rg`). Live
provider/model-spend gates remain explicit opt-ins and are not part of ordinary
CI.

- Preserve provider neutrality, exact authority and attempt binding, explicit
  budgets, typed uncertainty, and content-safe diagnostics.
- Keep credentials outside profiles, fixtures, logs, and committed evidence.
- Treat qualification records as scoped evidence, not transferable product
  claims.
- Do not enable registry or binary publication without an explicit policy
  change.

Report suspected vulnerabilities through `SECURITY.md`, not a public issue.
