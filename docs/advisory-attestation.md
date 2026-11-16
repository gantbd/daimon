# RustSec advisory attestation

Status: clean root-lockfile audit against a pinned current RustSec database;
not an SBOM, source review, provider assessment, or legal opinion.

audited-at-utc: 2026-11-16T22:32:28Z
cargo-audit-version: 0.23.0
advisory-database-commit: 02e2517f457a359fc6d3440ea4560c8ea188fee8
advisory-database-commit-date: 2026-11-15T10:59:21+01:00
advisory-count: 1509
lockfile-sha256: b001d0a65096606edf64321b42d425057719862212e91583fcab59666f8fa9c5
dependency-count: 91
vulnerability-count: 0
warning-count: 0

The result was produced with `cargo audit 0.23.0 --no-fetch --deny warnings`
against the exact database commit above. No advisory is ignored. CI additionally
audits against the then-current database so pinned evidence cannot silently age
into a publication claim.

This covers the root coordinated-source lockfile only. It does not qualify live
providers, credentials, optional model-spend paths, deployment-specific sandbox
policies, or future dependency resolutions.
