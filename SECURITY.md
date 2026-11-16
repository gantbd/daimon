# Security policy

## Supported versions

Daimon has not made a production release. The `main` branch is the only line
currently considered for security fixes; historical snapshots and untagged
archives are unsupported.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, chat room, fixture, or qualification artifact. Use GitHub private
vulnerability reporting when available, or contact the repository owner
privately through their GitHub profile to establish a confidential channel.

Include the affected revision, impact, preconditions, and a minimal synthetic
reproduction. Never attach provider credentials, bearer tokens, private prompts,
tool results, checkpoints, launch environments, or unredacted process material.

## Security boundary

Daimon executes already-authorized work through bounded provider adapters. It
does not create authority, decide scheduling, authenticate remote principals,
make provider processes trustworthy, or turn model output into permission. The
selected local profiles rely on exact Aegis and Chronos evidence, explicit host
configuration, private local IPC, and profile-specific process containment.
See `docs/operating-rigor.md`, `docs/local-model-harness.md`, and the provider
qualification documents for controls and residual limits.
