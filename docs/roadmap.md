# Roadmap

## Phase 0 — protocol closure

- Close request, budgets, context references, tool capabilities, outcomes, and
  evidence vocabularies.
- Threat-model prompt injection, confused deputy, tool escalation, secret leakage,
  replay, cancellation races, and resource exhaustion.
- Define the fake-provider contract used by Moira's first vertical slice.

## Phase 1 — deterministic fake harness

- [Implemented] Prepare/dispatch, authority/tool/budget validation, idempotent
  matching replay, conflicting replay, and bounded result evidence are implemented.
- Add cancellation, timeout, saturation, and shutdown scenarios.
- [Implemented for the model family] Produce bounded Agora-message and Vellum-edit
  proposals without publishing them.

## Phase 2 — connector protocol

- [Implemented, volatile profile] Native protocol, host ports, serialized service
  and capability-shaped clients with current authorization on retained delivery,
  exact-attempt validation before first dispatch, sticky outcome uncertainty and
  principal-scoped inspection.
- [Implemented against public Aegis service] Profile and every distinct tool
  require current `Daimon/Execute`; epoch revocation blocks retained delivery
  without another provider call.
- [Implemented against public Chronos client and real service] A bounded explicit
  task-key registry and exact running incarnation/attempt snapshot gate new
  dispatch. The real-service journey is isolated behind its own sovereign lock.
- [Implemented in four processes] Moira execution composes the real Aegis daemon,
  real running Chronos service and Daimon daemon through public clients before a
  create-once provider is invoked. The composed journey now discards the result
  reply, reopens Daimon's durable store in a fresh daemon, reauthorizes retained
  delivery through the still-live Aegis authority and proves neither Chronos nor
  the provider is called again.
- [Implemented store contract] Commit the outcome-unknown marker before provider
  dispatch, commit the exact result before publication, reconstruct identity and
  result state on reopen, and fence indeterminate marker/result commits without
  redispatch.
- [Implemented local store] Canonical bounded V1 service checkpoint over a
  receipt-gated exclusive private-directory mechanism, with missing-state refusal,
  lifetime ownership and exact result replay after actual filesystem reopen.
- [Implemented through real socket reopen] Canonical bounded V1 wire encoding,
  authenticated session binding, private Unix daemon, bounded requests, I/O
  deadlines, 0600 socket publication and exact-inode teardown. Real socket and
  filesystem reopen returns the exact result without provider redispatch.
- [Implemented] Actual process exit/reopen and discarded-reply reconciliation
  through Moira's public-client execution path, with an external provider marker
  proving no redispatch.
- Define provider and tool ports plus attributed receipts.
- [Implemented for lost reply plus restart] Qualify one local fake process adapter
  with fault injection. Broader provider failure injection remains open.
- Add unknown-effect reconciliation before any live model connector.

## Phase 3 — selected provider

- [Implemented] Select and document terminal OpenAI-compatible chat completions
  over loopback as the first model wire profile. Structured tool execution remains
  deferred.
- [Implemented and live-qualified] Exercise the real HTTP codec against an injected
  loopback server, including strict typed proposals, usage absence, profile drift
  and bounds. The separately enabled `qualify-openai-live` gate has also completed
  one bounded, non-retried request against the installed Ollama `gemma3:27b`
  model with nonempty output, provider usage and exact profile attribution.
- [Implemented through live transport] Integrate Dendrite as optional bounded
  grounding with exact authority/surface verification. The selected loopback MCP
  Streamable HTTP client handles chunked SSE `query_surface` and `read_ref`
  results without retry or redirect, and the local composition accepts retained
  expected digests through a separate example profile.
- [Implemented additive stack] Promote model execution through protocol, service,
  canonical wire, durable checkpoint, client and dedicated local daemon families.
- [Implemented agent delivery] Publish the independent canonical agent family
  through a dedicated authenticated 0600 Unix endpoint and matching client port,
  with connection-session substitution refusal, bounded request count and
  outcome-unknown classification after a lost reply.
- [Implemented local composition] A configuration-validated executable consumes
  existing Aegis and Chronos public sockets, a frozen loopback model profile,
  bounded static context and the durable model store before binding the dedicated
  Daimon model socket. Secrets remain environment-sourced and outside profile
  digests and checkpoints.
- [Implemented through Moira native service] Retain Daimon model results and
  dispatch typed Agora and Vellum proposals under separate stable Moira effect
  identities. The ordered/fenced proposal set has canonical persistence, a
  separate SQLite owner and a public service/client contract. Private wire/daemon
  promotion and the combined reply-loss matrix remain open.
- [Implemented, hermetically qualified] Add a distinct Claude Agent SDK
  stream-JSON adapter rather than presenting Claude as ACP. Exact launch and
  cleared-environment policy, initialize, bounded multi-slice output, verified
  context, one-shot permissions, cancellation (including while permission is
  pending), close, unknown-envelope fencing, post-dispatch process-exit
  uncertainty without relaunch, and non-consuming stale permission refusals
  pass against a credential-free process fixture. Exact environment allowlisting
  after `env_clear`, redacted launch diagnostics, and conservative
  completion-before-interrupt cancellation races are also qualified. Both
  interactive adapters now share a digest-bound macOS Seatbelt launch path;
  deny-default process gates prove file-write denial and successful protocol
  negotiation. Linux isolation and deployment-specific policy review remain
  open. Installed
  Claude Code `2.1.311` also passes the genuine
  no-prompt initialize/close gate. A bounded live prompt gate now exists behind
  an explicit model-spend opt-in. A 2026-11-16 run reached the provider and
  received assistant output, but failed closed because its terminal envelope
  combined a `success` subtype with `is_error=true`; a completed live turn
  remains open. A second run explicitly pinned `sonnet` but returned no terminal
  envelope within the full 120-second bound; it also remained unqualified.
- [Implemented and executed; remains opt-in] Run the upstream experimental ACP
  agent TCK only through an explicit model-spend target using a separately pinned
  executable, scratch workspace and retained JSON report. The 2026-11-16 v0.3.0
  comparison found Codex ACP 1.8.0 non-conformant because advertised delete and
  resume requirements failed, while a disposable 2.6.0 install passed all 32
  mandatory and all 19 exercised advertised-capability requirements. Three
  advisory and one informational requirements still failed on 2.6.0. This is
  provider-agent evidence and complements rather than replaces Daimon's
  client-adapter tests.
- [Current qualified provider floor] A disposable
  `@agentclientprotocol/codex-acp` 2.6.0 bridge passes initialize, session create,
  one bounded no-tool prompt with nonempty assistant output and a completed
  terminal event, and close through Daimon's adapter. A separate read-only-mode
  gate also passed a genuine typed permission challenge by selecting its exact
  `RejectOnce` option, granting no capability, retaining terminal evidence and
  verifying the nonexistent target remained absent. The installed 1.8.0 bridge
  retains historical adapter-gate evidence but is below the TCK-qualified floor.
  A hermetic Daimon-owned executable restart/recovery journey now passes. The
  genuine pinned 2.6.0 provider also passes fresh-process restart/reattach after
  one explicitly authorized no-tool seed turn, with zero history replay.
- [Implemented and genuinely provider-qualified] Separate the durable
  Daimon session graph from its ephemeral provider-process binding. Add a
  bounded host-only recovery
  locator, a visible reattachment-required state, and an explicit revisioned
  `Reattach` operation with fresh authority/attempt admission and the normal
  outcome-unknown commit fence. The ACP v1 projection must use `session/resume`
  without history replay and initially admit only a retained idle session.
  Active-turn loss remains outcome-unknown; startup must not auto-resume or fall
  back to `session/new`. Qualify canonical checkpoint/wire behavior, ambiguous
  commits, exact idempotent replay, a hermetic two-process adapter journey, and a
  genuine 2.6.0 restart/resume journey. The guarded genuine-provider gate now
  passes. An isolated
  no-prompt run proved Codex removes an empty rollout and the next process fails
  closed, so executing the final gate requires one explicitly authorized bounded
  seed turn before process exit; the authorized gate then proved exact
  fresh-process resume without history replay or fallback session creation.
- [Externally blocked credential lane] The installed Gemini CLI `0.68.0`
  negotiates ACP v1, but this host's `oauth-personal` lane is an individual
  account path that Google stopped serving in Gemini CLI on 2026-06-18. Its
  `UNSUPPORTED_CLIENT` occurs during `session/new` authentication before the
  installed provider examines ACP client filesystem capabilities. Daimon must
  not disguise that entitlement rejection as a protocol workaround; a
  separately and explicitly selected API-key or enterprise credential lane
  remains to be qualified.
- [Live mixed transport qualified] `make qualify-agent-router-live` opens real
  installed Codex ACP and Claude stream-JSON sessions through one bounded router,
  verifies exact frozen-profile attribution, and closes each through its retained
  route. The 2026-11-16 run passed without a model prompt; a mixed-provider
  prompt ensemble remains open.
- [Implemented production read callback] Keep ACP client filesystem access
  attenuated by default and advertise reads only for an exact configured
  workspace scope and tool capability. The local-agent governor carries prompt/
  continuation logical time, shares the service's session-bound Aegis and
  current-attempt Chronos guards, resolves symlinks before containment, emits
  digest-bearing canonical read evidence, and passes the real four-process
  recovery journey. Writes remain closed.
- [Implemented and production-qualified] Add the default-off ACP
  terminal lifecycle as a session-owned host port: create carries exact current
  authority/attempt inputs, output is bounded UTF-8 evidence, wait is deferred
  without blocking the sole transport writer, and kill/release plus cancel,
  close and owner loss attenuate handles. The hermetic full-lifecycle and cancel
  gates pass. The local-agent owner enables it only for an exact configured
  workspace/capability and rechecks live Aegis authority plus the current
  Chronos attempt at create time.
- [Implemented and production-qualified] Add a
  Daimon-owned, pipe-mode process-group sidecar following Axon's proven owner
  boundary. Exact argv/cwd/env cross bounded length frames; output is
  backpressured; cancellation and owner EOF kill the group; the direct child is
  reaped. The synchronous manager owns framing and output credit, requires
  absolute executables plus an explicit clean environment, retains a bounded
  valid UTF-8 suffix, polls exit, and waits for cleanup on cancellation/drop. A
  live mechanism gate proves owner loss removes both a direct child and its
  spawned descendant. The production composition canonicalizes the boundary,
  workspace and absolute command registry, enforces approved argv prefixes,
  cwd containment and clean allowlisted environment names, and has no raw
  subprocess fallback. Its real-process journey reopens exact terminal evidence
  after daemon restart. Broader command-policy and deployment isolation review
  remain environment-specific.

## Phase 4 — reusable operations surface and standalone CLI

- Define `daimon-tui` as a composable presentation over Daimon's public client.
  It owns bounded execution, provider, and supervised-agent projections plus
  local confirmation state; it does not own terminal lifecycle, CLI parsing,
  daemon/provider startup, global shortcuts, or process exit.
- Provide a separate Daimon CLI/application composition root that can select an
  embedded or remote service and run either the TUI or bounded headless inspect,
  dispatch, and supervisor operations.
- Let Workbench reuse the same TUI and optionally host the Daimon service and
  selected provider beneath one process lifecycle. Daimon continues to own
  execution authority, tool policy, provider effects, receipts, and uncertainty.
- Qualify standalone interactive/headless and Workbench interactive/headless
  paths with identical authorization, no-redispatch, cancellation, and
  outcome-unknown behavior.

