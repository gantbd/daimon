# Requirements

Status: deterministic core, native model service, canonical wire, authenticated
local daemon, exclusive durable store, runnable loopback OpenAI-compatible
composition, live digest-verifying Dendrite grounding and Moira-owned durable
proposal saga selected; multi-process cross-peer qualification remains open.

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
- **D10 — Public boundary:** peer integrations use a transport-neutral client and
  protocol contract; current authority, exact task-attempt validation and provider
  invocation remain trusted service ports rather than client-supplied evidence.
- **D11 — Frozen provider selection:** the complete non-secret local provider
  profile is digest-bound before admission; credentials remain host-only and may
  rotate without changing retained execution identity.
- **D12 — Exact grounding:** optional Dendrite evidence is accepted only when the
  exact authority bytes and canonical projected surface match their authored
  SHA-256 identities. Dendrite receives no consumer lifecycle identity.
- **D13 — Proposal sovereignty:** model output may contain bounded typed Agora and
  Vellum proposals, but Daimon never treats them as peer-effect receipts or submits
  them directly.
- **D14 — Interactive-agent separation:** stateful agent sessions use a distinct
  protocol family. Session open, prompts and permission decisions carry exact
  authority/attempt/idempotency inputs; thought, plan, tool, terminal,
  permission, file-change, usage and terminal assistant results remain distinct
  events. A provider returning to ready is not completion evidence without a
  matching terminal event. Reattaching a retained session after provider-process
  loss is an explicit, durably fenced execution effect: it is never an automatic
  startup retry, never replays provider history into canonical event cursors, and
  never claims an active turn was recovered without separately modeled terminal
  evidence.

The selected Aegis adapter checks `Execute` on the profile and every requested
tool through Aegis's public client and rechecks on retained delivery. The first
provider profile is terminal OpenAI-compatible chat completions over loopback
HTTP/1.1 with no retry, redirect or streaming semantics. Open: sandbox mechanism,
structured tool execution, general context assembly, model attestation,
peer-credential policy, signal/cancellation qualification, and production SLOs.

The selected Chronos adapter resolves the opaque task key only through a bounded
deployment registry and accepts only a public snapshot whose task name,
incarnation, running phase and attempt number all match. It never imports a lease
or Chronos engine value into Daimon's protocol.

