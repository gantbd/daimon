#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

for required in CHANGELOG.md CONTRIBUTING.md LICENSE-APACHE LICENSE-MIT README.md SECURITY.md rust-toolchain.toml release/github-source.json docs/advisory-attestation.md docs/operating-rigor.md docs/traceability.md; do
  [[ -s "$required" ]] || { echo "missing Daimon public-source file: $required" >&2; exit 1; }
done

rg -q '^channel = "1\.95\.0"$' rust-toolchain.toml || { echo 'Daimon toolchain is not pinned' >&2; exit 1; }
rg -q '"channel": "github-coordinated-source"' release/github-source.json || { echo 'Daimon GitHub source channel missing' >&2; exit 1; }
rg -q '"remoteReachabilityQualified": true' release/github-source.json || { echo 'Daimon source reachability is not qualified' >&2; exit 1; }
rg -q '"qualificationRevision": "325e662a6a945cf8a064b9812ebbbdac02be4130"' release/github-source.json || { echo 'Daimon source qualification revision drifted' >&2; exit 1; }
for revision in 2e4faf10ec0a70805aa1db1555f93c77fcf0a1e4 b272106cf6d0093839a7d696c829bf8a408b0306 ebff27188388cd0249d07751b1cc848c6ef1a3f9; do
  rg -q "\"revision\": \"$revision\"" release/github-source.json || { echo "Daimon source revision missing: $revision" >&2; exit 1; }
done

expected=$(awk -F': ' '$1 == "lockfile-sha256" { print $2 }' docs/advisory-attestation.md)
actual=$(shasum -a 256 Cargo.lock | awk '{print $1}')
[[ -n "$expected" && "$actual" == "$expected" ]] || { echo 'Daimon root lockfile changed without a new advisory attestation' >&2; exit 1; }
rg -q '^name = "rustix"$' Cargo.lock
rg -q '^version = "1\.1\.6"$' Cargo.lock

echo 'Daimon public-source contract pins its exact peer closure and evidence'
