# Daimon

Daimon is the provider-neutral agent harness protocol and execution runtime.
It executes already-authorized work under explicit budgets and returns attributed
evidence. It does not decide which work exists, schedule retries, define room
behavior, or own document publication.

Moira requests execution, Chronos owns the task lease, Aegis supplies authority,
optional Dendrite calls supply authored grounding, and Vellum handles document
edits. Model and tool providers remain adapters.

The deterministic core now implements both the original fake-artifact path and an
additive model path with frozen provider profiles, exact context evidence, observed
token budgets, attributed output and typed Agora/Vellum proposals. The selected
local provider adapter performs one bounded OpenAI-compatible loopback HTTP call;
the core itself remains provider- and I/O-neutral. See [requirements](requirements.md),
[specification](specification.md), the [local model profile](docs/local-model-harness.md),
and the [roadmap](docs/roadmap.md).

## Native service boundary

`daimon-protocol` owns transport-neutral execute and principal-scoped status
values. `daimon-host` defines explicit current-authority, exact-attempt and
provider ports. `daimon-service` composes those ports with the sovereign harness,
and `daimon-client` exposes disjoint execution and read-only facades. An
authenticated service session binds the caller principal and opaque authority
context outside the command payload.

The default constructor selects a volatile store, while the generic
`ExecutionStore` port supports recovery-qualified persistence. The service commits
an execution as outcome-unknown before invoking its provider, never automatically
redispatches that execution, requires current authorization before returning a
retained result, and exposes status only to the bound principal. It commits the
exact result before publication. Tests prove exact reopen, an indeterminate marker
commit fences before the provider, and a lost result-commit reply recovers the
winner without redispatch. `daimon-checkpoint` owns the canonical bounded service
snapshot and receipt gate; `daimon-local` binds it to Keystone's exclusive private
directory store. Actual directory reopen preserves the exact result and provider
call count. `daimon-wire` supplies the canonical bounded V1 request, reply and
session-opened frames. `daimon-local-daemon` binds an authenticated session to a
private Unix connection with bounded request count, I/O deadlines, a 0600 socket
and exact-inode teardown. Real socket plus filesystem reopen returns the exact
result without provider redispatch. The isolated Moira qualification closes the
separate-process recovery gate. That profile discards an execution reply, exits the daemon, reopens a
fresh process and obtains the exact Moira receipt while an external provider
marker proves one dispatch.

The model family follows the same layout without changing any legacy frame or
checkpoint meaning: `daimon-protocol` DTOs, trusted host profile/context/provider
ports, `daimon-service::model`, independent canonical wire/checkpoint codecs,
capability-shaped clients, exclusive local storage and a dedicated authenticated
Unix endpoint. `daimon-openai-local` selects terminal OpenAI-compatible chat
completions with canonical non-secret profile digests, no implicit retry and
mandatory usage evidence. `daimon-dendrite` optionally verifies exact authority
and projected-surface digests before context can enter an invocation.

An additive interactive-agent contract is now present in `daimon-protocol`,
`daimon-host`, `daimon-service`, and `daimon-client`. It keeps interactive
sessions distinct from terminal model completion: opaque session/turn/
permission identities, frozen credential-free launch policy, negotiated
capabilities, typed cursor-ordered events, revisioned mutations, exact prompt
digests, and honest outcome-unknown state. The volatile reference service
crosses authority and exact-attempt validation before both session open and
prompt dispatch, refuses a provider's return-to-ready without a matching
terminal event, and replays a retained turn without provider redispatch. A real
`daimon-acp` now provides the ACP v1 process projection: exact host-owned
launch/workspace registries, bounded line framing, background stdout ownership,
cooperative progress, typed permissions, cancellation on the pending prompt,
verified-context projection, capability-aware close, child reap, and no
implicit retry. Capability projection follows ACP v1 value semantics: boolean
`loadSession`, non-null object markers for optional lifecycle support, and valid
mode/legacy-model state from the successful `session/new` result. Empty,
inconsistent, false, null, malformed, or misplaced values are not promoted into
Daimon capabilities.
Idle ACP sessions that return an opaque bounded resume locator persist it only
inside Daimon's checkpoint. Reopen exposes `ReattachRequired` and performs no
provider I/O. The explicit revisioned `Reattach` mutation revalidates the exact
retained principal/profile/context/tool/attempt scope, commits its uncertainty
fence, launches a fresh adapter process, and uses ACP `session/resume` without
history replay or an implicit prompt. Active-turn loss and providers without a
matching resume capability remain outcome-unknown. A second restart creates a
new binding generation and therefore requires a fresh revision/key pair rather
than redispatching a completed prior reattach.
Inbound lines must also be valid JSON-RPC 2.0 request, notification, or response
objects; missing versions, fractional identities, mixed result/error envelopes,
and malformed errors are rejected before ACP method dispatch.
Session updates are admitted only as ID-free notifications for the exact remote
session returned during setup; cross-session or request-shaped updates cannot
become Daimon event evidence. Assistant/thought events require an ACP text
content discriminator, so an extension field on another content kind cannot be
reinterpreted as model text.
Deployment configuration may freeze one advertised
agent-handled authentication method into the launch digest; the adapter invokes
it once between initialize and session creation, rejects ambiguous or terminal
descriptors, and carries no credentials. Its optional host-owned ACP
filesystem-read port is attenuated
off by default; a hermetic gate proves exact canonical execution binding,
bounded UTF-8 response handling, digest-bearing read evidence, and false
advertisement when no governor is installed. The production local-agent
composition enables it only for canonical configured workspace roots and an
exact tool capability, then reauthorizes through its live session-bound Aegis
client and revalidates the current Chronos attempt at callback time. Its
real-process gate reopens the digest-bearing read evidence after daemon restart.
The ACP adapter also exposes a default-off, host-owned terminal lifecycle port
covering create, bounded output, deferred wait, kill and release. Its hermetic
gate proves exact callback binding, ACP signal-string exit status, canonical
terminal evidence and release on cancellation. The production local-agent does
advertise it only for an explicit workspace scope whose capability is granted.
That governor canonicalizes an absolute boundary and command registry, admits
only approved argv prefixes, cwd containment and environment names, and reruns
fresh Aegis/Chronos checks at create time; there is no raw subprocess fallback.
`daimon-process-boundary` and its `daimon-process` manager are now the separately
owned pipe-mode containment layer for that composition. It accepts only
length-framed exact argv/cwd/env
material, applies bounded output backpressure, reports its actual process-group
mechanism, kills the group on cancellation or owner-pipe loss, and reaps before
exit. The manager requires an absolute boundary executable and absolute target
argv, clears and validates the explicit environment, owns output-credit writes,
retains a valid UTF-8 suffix, polls exit without blocking, and waits for cleanup
on cancellation or drop. Mechanism tests prove owner loss removes both the
direct child and a spawned descendant. This layer is not command authorization;
the registry and fresh authority/attempt governor still precede launch.
Hermetic process-loss gates additionally prove that exit after
prompt dispatch becomes outcome-unknown and that `Advance` never relaunches the
provider; stale request and option identities leave the exact valid permission
challenge available. Process children receive only an exact environment-name
allowlist after a full clear, and launch diagnostics redact arguments and those
names. A completion winning an ACP cancellation race remains completed rather
than being rewritten as cancelled. Both interactive adapters share an optional
digest-bound macOS Seatbelt launch mechanism; deny-default gates prove blocked
file mutation and successful provider negotiation. Linux isolation and
deployment-specific policy adequacy remain open. A disposable
`codex-acp` 2.6.0 bridge has passed the pinned upstream ACP v1 TCK (32/32
mandatory and 19/19 exercised advertised-capability requirements) plus Daimon's
independent lifecycle, bounded no-tool prompt, exact reject-once permission,
and genuine fresh-process restart/reattach gates. The restart gate used one
explicitly authorized no-tool seed turn and observed zero history replay. The
installed 1.8.0 bridge passed those Daimon paths but failed the TCK's
advertised delete and resume requirements, so it is historical evidence rather
than the qualified provider floor. The installed Gemini CLI negotiates ACP v1 but
its selected individual-OAuth lane is provider-deprecated and returns
`UNSUPPORTED_CLIENT` before session creation; qualification through an
explicitly selected supported API-key or enterprise lane remains open. No
Claude ACP bridge is installed. The exact evidence and non-claims are in
[`docs/acp-provider-qualification.md`](docs/acp-provider-qualification.md).
Claude Code is now represented by a separate `ClaudeAgentStreamJson` profile,
not an ACP alias. `daimon-claude` freezes and bounds the official bidirectional
Agent SDK NDJSON/control transport, including initialize, verbatim prompts,
typed assistant/tool/usage events, exact one-shot permission choices,
correlated interruption and child teardown. Its credential-free hermetic gate
also covers post-dispatch provider exit without relaunch and non-consuming
stale permission request/option refusals, plus the same cleared allowlisted
environment and redacted launch diagnostics. If a Claude result wins the race
with the required interrupt acknowledgement, cancellation is conservatively
outcome-unknown rather than falsely successful. It
passes, and installed Claude Code `2.1.311` has passed the genuine initialize/
close transport gate without a model call. Its bounded prompt gate is now
implemented behind an explicit model-spend opt-in. A 2026-11-16 run reached the
provider and received assistant output, but the provider marked its terminal
`success` subtype with `is_error=true`; Daimon retained failure and did not
claim completion. See
[`docs/claude-provider-qualification.md`](docs/claude-provider-qualification.md).
`daimon-agent-router` composes those distinct transports behind the single
provider-neutral host port. Administrator-registered frozen profile digests
select a backend; the route is fenced before open dispatch and retained across
an ambiguous result. Its hermetic process gate runs simultaneous ACP and Claude
sessions through one router and verifies distinct attributed event streams and
terminal close without provider fallthrough. The opt-in
`qualify-agent-router-live` gate also passed against installed `codex-acp` 1.8.0
and Claude Code 2.1.311: both real sessions opened concurrently with exact
profile attribution and closed through their retained routes without submitting
a model prompt.
`daimon-local-agent` is the matching production application composition. Its
strict configuration derives launch digests from exact program, argv and
inherited-environment names, assembles bounded digest-verified context, connects
through Aegis and Chronos public clients, owns the durable agent checkpoint and
serves only the dedicated authenticated agent socket. `--check` performs those
closed configuration checks without contacting a peer, opening storage, binding
a socket or starting a provider.
The example configuration freezes three provider lanes behind that same
contract: Codex through ACP, Gemini CLI through native `--acp`, and Claude Code
through its distinct stream-JSON transport. Credential values remain host-only;
only exact environment names enter the launch profile. The Gemini example is a
configuration path, not a qualification claim for the unavailable credential
lane on this host.
The agent service has a durable-store
port, exact preparation attribution, restart reconstruction, marker/result
commit fencing, an independent bounded canonical checkpoint, and exclusive
private-directory composition. The independent
canonical agent wire covers every command, outcome, refusal and typed event
under prompt/event/option/frame limits without widening legacy or model frames.
`daimon-local-daemon` publishes that family on its own authenticated 0600 Unix
endpoint, and `daimon-client` supplies a matching `AgentUnixPort`. The
connection-issued service session cannot be replaced by a frame, requests are
bounded per connection, and a reply lost after dispatch is reported as
outcome-unknown rather than retried.
Exact permission decisions are separately authority/attempt-gated and
replay-safe. Cancel and close are owner-scoped, revisioned, replay-safe
authority attenuations: active work must be cancelled before close, and a
successful cancellation requires matching cancelled terminal evidence.
Active turns advance through a separately revisioned, idempotent, durably
fenced `Advance` mutation. It grants no new execution authority, admits only a
bounded progress observation (including an honest empty still-active slice),
permission request, or terminal evidence, and leaves
the service free to accept cancellation while an ACP prompt remains pending.

`daimon-aegis` implements the execution-authority port through Aegis's public,
session-bound client. It requires current `Daimon/Execute` decisions for the
selected profile and every distinct requested tool. The Daimon session carries
only an opaque binding to the application-issued, session-local Aegis grant;
the grant handle never enters Daimon's protocol or configuration. A real Aegis service journey proves allowed execution
and proves epoch revocation blocks retained-result delivery without another
provider call.

`daimon-chronos` implements exact-attempt validation through Chronos's public V1
snapshot client. A bounded explicit deployment registry maps Daimon's opaque task
keys to Chronos task names; neither identity is inferred or treated as authority.
Only the exact running incarnation and attempt is current. Unknown mappings and
phase/identity drift are not current, while transport or malformed peer evidence
is unavailable. An isolated real-service qualification creates and claims a real
Chronos task, then proves exact allow and stale-attempt denial without merging
Chronos's sovereign storage graph into Daimon's root lockfile.

The selected local daemon profile and its trust boundary are documented in
[local daemon](docs/local-daemon.md).

## Running a local model profile

`daimon-local-model` is the composition-only executable. It issues an exact
profile/tool grant on its own authenticated Aegis session, validates the exact
running Chronos attempt, opens Daimon's durable model store, freezes one loopback
OpenAI-compatible profile and serves the model protocol on a private Unix socket.
It does not schedule work or submit Agora or Vellum effects; Moira retains those
responsibilities.

Copy `config/local-model.example.json`, replace the opaque identities, socket
paths, task mapping and context, then validate it without opening any service or
store:

```sh
cargo run -p daimon-local-model --locked --offline -- \
  --check config/local-model.example.json
```

Run it after the selected Aegis and Chronos services and the loopback model server
are ready:

```sh
cargo run -p daimon-local-model --release --locked --offline -- \
  config/local-model.json
```

For endpoints requiring a token, set `bearer_token_env` to an environment-variable
name. The token is loaded at startup and excluded from the frozen profile digest,
checkpoint, protocol and diagnostics. The example uses structured-output mode so
Agora/Vellum proposals are parsed through the strict schema. Static context is
included as exact model messages and separately retained as digest-attributed
evidence; Dendrite-backed context uses the adapter contract described in the
[local model profile](docs/local-model-harness.md).

An already-installed loopback provider can be qualified independently of the
composition daemon:

```sh
make qualify-openai-live DAIMON_OPENAI_LIVE_MODEL=gemma3:27b
```

The gate performs one bounded OpenAI-compatible request without retry and
requires attributed nonempty output plus provider-reported token usage. It does
not download a model or treat generated text as an Agora/Vellum receipt.

For live Dendrite grounding, start from
`config/local-model-dendrite.example.json`, replace both retained `sha256:`
digests with those returned by the selected Dendrite surface, and supply the
configured token environment variable. The bounded client makes one loopback
MCP Streamable HTTP call for `query_surface` and one for `read_ref`, parses the
chunked SSE result, and refuses any authority or canonical-surface drift before
the bytes enter the model messages.

## Development

```sh
make check
```

## SDK facade

`daimon-sdk-embedded` reexports the provider-neutral harness contracts without
selecting a provider, process sandbox, model, tool adapter, or runtime policy.

