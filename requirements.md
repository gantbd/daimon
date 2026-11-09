# Requirements

Status: proposed.

- **D1 — Work is external:** Daimon executes a supplied work request; it does not
  create goals, tasks, retries, or room responses autonomously.
- **D2 — Exact identity:** execution binds one stable execution ID, Chronos attempt,
  agent principal, harness profile, and idempotency key.
- **D3 — Explicit budgets:** time, model tokens, tool calls, output bytes, context
  bytes, concurrency, and retained evidence are bounded.
- **D4 — Capability tools:** only tools named by current Aegis authority and the
  request profile may be invoked.
- **D5 — Honest outcomes:** completed, failed, cancelled, timed out, and uncertain
  executions remain distinct; process exit is not completion evidence.
- **D6 — Idempotent dispatch:** matching replay cannot execute provider work twice;
  conflicting replay is refused.
- **D7 — Provenance:** results identify provider/model profile, tool receipts,
  produced artifacts, and bounded causal inputs without leaking secrets.
- **D8 — Provider isolation:** provider-specific payloads and SDKs remain adapters;
  the protocol is model-neutral.
- **D9 — Controlled shutdown:** outstanding work is cancelled, completed, or
  returned as unresolved evidence before ownership is released.

Open: sandbox mechanism, provider profiles, streaming, tool protocol, secret
delivery, context assembly policy, model attestation, and production SLOs.

