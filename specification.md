# Initial specification

The provider-neutral boundary is:

```text
prepare(HarnessRequestV1, AuthorityEvidence, Limits)
  -> PreparedExecution | Refusal

dispatch(PreparedExecution, ProviderReceipt)
  -> HarnessResultV1 | Uncertain
```

Preparation validates identity, current lease evidence, authority, profile, tools,
budgets, context references, idempotency, and capacity without invoking a provider.
Dispatch is an adapter effect. Accepted provider evidence is tied to the exact
prepared request and attempt.

Streaming is deferred. The first profile accepts one bounded terminal provider
result so cancellation, timeout, idempotency, and uncertainty can be closed before
incremental output complicates the state space.

No result directly mutates Agora, Chronos, or Vellum. It returns typed proposals and
evidence to Moira-owned integration logic.

The additive model boundary freezes a credential-free provider profile and exact
assembled input before one terminal admission:

```text
prepare_model(PreparedExecution, ProviderProfileSnapshot, ContextEvidence, Messages)
  -> ModelInvocation | Refusal

dispatch_model(ModelInvocation, ModelProviderReceipt)
  -> ModelExecutionResult { output, usage, evidence_digest, proposals } | Refusal
```

The selected adapter supports OpenAI-compatible chat completions over loopback
HTTP/1.1. It sends `stream: false`, follows no redirects, performs no implicit
retry and requires observed prompt/completion usage. Plain-text mode returns no
peer proposals. Strict mode requests a JSON schema whose only proposal variants
are Agora message and Vellum expected-revision edit. The adapter computes evidence
identity from the exact accepted context rather than trusting model-authored
provenance.

## Interactive agent sessions

The additive agent family does not reinterpret model `Execute`/`Resume` frames.
It owns opaque session, turn, permission-request and permission-option
identities; a credential-free provider profile snapshot; bounded session budgets;
negotiated capabilities; revisioned commands; and cursor-ordered typed events.
Provider credentials, argv and login state remain host-owned.

Opening a provider session and submitting a prompt are both execution effects.
Each therefore carries `ExecuteRequestV1` and crosses current authority, exact
Chronos-attempt validation and core budget admission before one provider call.
Matching replay rechecks authority and returns the retained observation without
redispatch. An ambiguous provider outcome remains `OutcomeUnknown`.

An assistant message is not terminal evidence. A provider receipt that returns
the session to `Ready` after a prompt must end with one matching
`TurnFinished`, whose disposition and stop reason agree. Permission-waiting and
active-turn receipts retain the exact active turn and cannot contain a terminal
event. Event cursors are contiguous, pages are bounded, prompt bytes are
digest-checked, and per-session turn/event/permission budgets are monotone.

Cancellation and close do not create new provider authority. They authenticate
the owning service principal, fence the exact session revision and retain an
idempotent outcome-unknown marker before one provider call. Cancellation is
valid only for the exact active turn and requires a final matching
`Cancelled/Cancelled` event before returning the session to `Ready`. Close is
valid only from idle `Ready`, requires a `Closed` receipt with no fabricated
events, and cannot replace cancellation of active work. Matching replay never
redispatches either attenuation.

The agent wire family has independent magic, versioning and limits. It encodes
the complete command, outcome, refusal and typed-event algebra canonically;
prompt bytes, event count/size, permission options, context references, tools
and total frame bytes are bounded before allocation. Truncation, trailing bytes,
unknown tags and cross-family frames fail closed. These limits do not widen the
legacy artifact or terminal model wire families.

Local delivery uses a dedicated private Unix endpoint, not protocol sniffing on
the legacy or model sockets. Authentication opens one agent service session;
the daemon binds every request to that connection-issued handle and refuses a
substituted frame handle before dispatch. The socket is mode 0600, has finite
I/O and request-count limits, and is removed only when its exact bound inode
still occupies the configured path. Client and server classify a failed reply
after request transmission as outcome-unknown and never infer a safe retry.

Durable agent state retains the exact authority decision, expiry, tool set and
preparation time for session open and every authority-bearing prompt or
permission operation. Recovery reconstructs the core execution identity index
from that attribution before accepting traffic; visible session state alone is
insufficient. Each provider call is preceded by a committed outcome-unknown
operation fence. An indeterminate marker commit suppresses dispatch, while an
indeterminate result commit returns uncertainty and is reconciled from the
durable observation on reopen without redispatch. Cancel and close retain no
invented execution authority but use the same durable operation fence.

The agent checkpoint is a separately versioned canonical codec over the full
retained session graph. It bounds sessions, operations, events, prompts,
permission options, context references, tools and total bytes before allocation;
requires canonical session and operation ordering; and rejects truncation,
trailing data, duplicate identities and weak checkpoint loads. The local
composition owns it through the same exclusive private-directory mechanism as
the terminal execution families.

### Provider binding recovery

The canonical Daimon session and its provider-process binding are different
facts. A checkpoint can prove the retained session graph, operation fences and
event cursors without proving that a newly constructed adapter still owns a live
connection to the provider's remote session. Recovery must preserve that
distinction instead of treating a durable `Ready` view as a live process handle.

The selected recovery design therefore introduces an explicit, revisioned
`Reattach` operation for an idle retained session. The provider adapter returns a
bounded opaque recovery locator when opening a resumable session. That locator is
host/checkpoint material bound to the frozen provider-document digest and exact
workspace; it is not a public client identity, model authority, credential, or
substitute for Daimon's session ID. A reopened service exposes that reattachment
is required but performs no provider call during checkpoint loading.

`Reattach` carries a fresh `ExecuteRequestV1`, the expected session revision and
its own idempotency key. It must cross current Aegis authority, exact Chronos
attempt validation, the frozen profile/context boundary and a committed
outcome-unknown marker before one provider invocation. Matching replay returns
the retained result without invoking the provider. Indeterminate marker or
result commits fence redispatch exactly as they do for open and prompt.

For ACP v1, the first supported projection is `session/resume`, not
`session/load`. Resume reattaches without replaying prior conversation history;
load replays `session/update` history and could duplicate Daimon's already
canonical cursor stream. Reattachment repeats initialize and any configured
agent-handled authentication, then sends the exact retained remote session ID,
canonical workspace and empty MCP-server set. Success requires an advertised
resume capability, the same frozen profile binding, a successful correlated
response, and capability/setup state that does not contradict the retained
session. No prompt is sent as part of reattachment.

The first slice is deliberately limited to a session that was durably idle and
`Ready`. A process loss with an active or permission-waiting turn remains
`OutcomeUnknown`: ACP allows work to continue or be cancelled after connection
loss, so a resume response alone is not terminal evidence for that turn. A
structured unknown-session response, an unsupported resume capability, and an
ambiguous transport outcome also require distinct modeled recovery outcomes
before implementation; none may be rewritten as a fresh `session/new`, silent
close, or prompt retry. Automatic startup resume is forbidden because it would
perform an unfenced external effect before a principal has supplied current
authority and attempt evidence.

## ACP process progression

ACP v1 authentication is negotiated from the successful `initialize` result.
The deployment may freeze one non-secret method identifier into the launch
profile. The adapter invokes it only when exactly one advertised descriptor has
that identifier and its type is absent or `agent`; it does so before
`session/new`. A missing or duplicate descriptor, a `terminal` descriptor, or
an unsuccessful authentication response fails session admission as
outcome-unknown. Terminal authentication commands are never interpreted or
executed by the ACP connection, and credential values remain outside protocol
and checkpoint state.

ACP v1 capability admission follows the schema's value semantics rather than
JSON member presence. `loadSession` is true only for the boolean `true`;
optional session capability markers such as `resume` and `close` are true only
for non-null objects. Session modes and legacy model state are learned from a
schema-shaped successful `session/new` result, including a current identity
present in the advertised set, not invented from initialize-time members or
empty objects. False, null, malformed, or misplaced values remain unsupported
in the provider-neutral receipt.

Every inbound ACP line must be one JSON-RPC 2.0 object with a valid request ID
shape and exactly one request/notification or response shape. A response cannot
carry both `result` and `error`; structured errors require an integer code and
string message. Malformed envelopes make the affected provider operation
outcome-unknown rather than being interpreted by field coincidence. A response
whose identity does not match the one outstanding client request is likewise
outcome-unknown; Daimon never sends a JSON-RPC response to another response.
Every `session/update` must be a notification without an ID and must name the
exact remote session returned by `session/new`. A request-shaped update or an
update for another session fences the turn as outcome-unknown before any bytes
can enter the canonical event stream.
Assistant and thought bytes are admitted only from ACP `text` content blocks.
An image, audio, resource, or future content variant cannot become text merely
because an extension field happens to be named `text`; unsupported variants are
left unprojected rather than semantically retyped.
Tool-call evidence requires the ACP `toolCallId`, and a new tool call also
requires its title. Plan evidence requires an entries array. Malformed
structured updates remain unprojected instead of being serialized into an
apparently valid Daimon tool or plan event.

ACP v1 keeps `session/prompt` pending while streaming updates and requires the
same connection to remain able to answer permission requests and send
`session/cancel`. Therefore a real adapter cannot hold the sole mutable service
call blocked until prompt completion. Daimon's process profile must project the
stream through an owned background reader and expose bounded, revisioned,
durably fenced advancement of an active turn (or an equivalent independently
owned projection). Cancellation and permission decisions must remain callable
while that prompt request is pending. A `TurnActive` receipt without a way to
advance and persist later updates is not a complete ACP implementation.

ACP client callbacks are separate governed effects, not an implication of a
permission prompt. Filesystem reads are advertised only when the host has an
exact frozen workspace scope and capability for the opened session. Each read
continuation carries canonical session, turn, workspace, execution/attempt and
logical-time evidence to a host governor. The governor must reauthorize through
the live authority port, revalidate attempt currency, resolve the absolute path
through canonical allowed roots, bound and validate UTF-8 content, and return a
safe relative path with a content digest. The adapter retains that receipt as a
typed event. Client writes remain unavailable. Terminals are default-off and
become available only through a host lifecycle port whose create operation has
the same exact session/turn/workspace/execution and continuation-time binding;
opaque handles remain session-owned, waits are nonblocking, and cancel, close,
or owner loss releases them. Production composition additionally requires a
process-group owner and command/cwd/environment policy before advertisement.
Terminals remain unavailable in the local application until those controls have
equivalent effect, uncertainty and recovery contracts. Provider-native tools
remain outside this callback and require separate process confinement.

The process-group owner is a distinct pipe-mode sidecar, not the provider
adapter and not a shell. Exact argv, cwd and an explicit environment cross a
bounded framed channel. Output is credit-controlled. Cancellation or owner EOF
kills the group and the sidecar reaps its direct child before exiting. The
reported platform mechanism remains evidence; it is not a claim that every
platform supplies identical containment, nor does containment replace command
authorization.

The in-process manager is the sole sidecar control writer. It admits only an
absolute configured boundary executable and an absolute target executable,
clears and validates a unique explicit environment, acknowledges each bounded
output frame, retains a valid UTF-8 suffix at the requested byte limit, and
exposes nonblocking exit observation. Cancellation returns only after the
sidecar reports its terminal disposition and exits; dropping the manager closes
the owner pipe and waits for cleanup.

The provider-neutral contract implements this as `Advance`: an owner-scoped,
exact-turn, expected-revision and idempotency-fenced mutation carrying no new
execution grant. Each call performs at most one provider admission and returns
a bounded progress observation, an exact permission request, or terminal
evidence. An empty active observation means only that no update arrived within
the configured slice; it is not transport uncertainty. Its marker and admitted receipt follow the same durable
uncertainty laws as cancel and close.

## Claude Agent stream-JSON progression

Claude Code's Agent SDK transport is a separate wire profile, not an ACP
dialect. The selected adapter owns one long-lived, bounded NDJSON process per
Daimon session, clears the child environment before copying an explicit
host-owned allowlist, freezes the official stream input/output and stdio
permission flags, and proves an `initialize` control response before returning
`Ready`. Prompts are marked `client_composed` so provider-side path and command
expansion cannot reinterpret Daimon's exact prompt/context envelope.

`can_use_tool` control requests become exact canonical permission events. The
initial profile exposes only `AllowOnce` and `RejectOnce`: the allow response
echoes the provider's original structured input, while rejection adds no
persistent provider permission rule. Cancellation first resolves any blocking
permission as an interrupting denial, then requires a correlated `interrupt`
control response and a terminal provider result before emitting the canonical
cancelled terminal event. Malformed, oversized, uncorrelated or unsupported
envelopes produce `OutcomeUnknown`; they are never retried or reinterpreted as
completion.

## Native application boundary

The public command contains the bounded execution request and caller-supplied
logical time, but no authority evidence, Chronos lease or provider receipt. A
trusted authentication adapter opens a principal-bound session. The application
service asks separate host ports for current Aegis authorization and exact
Chronos-attempt validity before preparing a new execution, then calls one selected
provider port.

Before the provider call the service retains `OutcomeUnknown`. A provider receipt
can advance that entry to `Completed`; an uncertain provider return leaves the
fence in place. Matching client replay rechecks current authority and observes the
retained result or fence without another provider call or attempt validation.
Changed input under either the execution identity or idempotency identity refuses.
Read-only status is principal-scoped and contains no request content.

The default application constructor is volatile. The generic service-store port
retains the original request, authority attribution used for semantic
reconstruction, provider-call fence and exact result. A new execution snapshot
must commit as `OutcomeUnknown` before the provider is called. The exact terminal
result must commit before publication. Indeterminate marker commitment suppresses
provider dispatch; indeterminate result commitment returns uncertainty and requires
reopen. Recovery rebuilds the harness identity/idempotency indices and completed
evidence without invoking the provider. These laws are qualified against an
independently controlled store.

`daimon-checkpoint` selects one canonical V1 snapshot with strict execution-ID
ordering, bounded context/tool/artifact vectors, exact result identity and no
trailing bytes. It gates publication on an exact durable Keystone storage receipt
and refuses weak load evidence, missing existing state, revision conflict and
invalid receipts. `daimon-local` selects Keystone's exclusive private-directory
mechanism: explicit creation never adopts an existing path, reopen never creates
missing state, and a lifetime lock prevents a second cooperating owner. This is
a trusted local single-owner profile, not authenticated storage, rollback
detection, network-filesystem support or physical power-loss certification.

The model service/store family is separately identified. Its outcome-unknown
marker retains the complete invocation: provider document digest, exact context
bytes and source/grounding identities, messages and estimated input usage. Its
completed state retains exact observed tokens, output, evidence digest and typed
proposals. Restore semantically replays those values through the core and never
re-resolves a provider profile, re-queries context or redispatches the model.

`daimon-dendrite` is an optional context assembler. It reconstructs Dendrite's
ordered canonical surface JSON and verifies its SHA-256 digest, separately reads
and hashes the exact authority bytes, and compares both to the caller-retained
expected identities. Its client port contains only load ID, target and authored
depth; no execution, provider, attempt or checkpoint identity crosses the boundary.
The selected transport is bounded loopback MCP Streamable HTTP: one
`query_surface` and one `read_ref` call, structured chunked-SSE parsing, no
redirect and no implicit retry. The local composition can select this adapter
with retained expected digests or start without Dendrite.

The selected `daimon-aegis` authority-port implementation binds one authenticated
Daimon principal and opaque authority context to a session-owned Aegis grant. It
requests current `Daimon/Execute` decisions for the exact profile resource and
each distinct tool resource. The earliest expiry bounds the core authority fact.
Profile/tool IDs share Aegis's Daimon resource namespace and therefore must not
alias semantically different deployment resources. Revocation or expiry refuses
even retained-result delivery; no decision summary is treated as bearer authority.

The selected `daimon-chronos` attempt-port implementation maps a fixed Daimon
task key to one configured Chronos task name. It reads only Chronos's public V1
snapshot and accepts the request when that observation has the exact configured
name, incarnation, running phase and attempt number. A missing mapping, absent
task, non-running phase or identity drift is `NotCurrent`; transport failure or
invalid response evidence is `Unavailable`. The registry is finite and rejects
duplicate keys or task-name aliases. No lease, worker grant or scheduling command
crosses this boundary.

## Private local transport

`daimon-wire` is the canonical bounded V1 encoding for execute, inspect, every
reply outcome/refusal, and the server-selected session handle. Decoding rejects
unknown tags, oversized vectors/frames, truncation and trailing bytes. Mutation
qualification requires any accepted mutated frame to re-encode byte-for-byte.

Model request/reply frames have distinct tags and independent context, output and
proposal limits. A legacy decoder rejects them as unsupported. Model clients and
read-only clients likewise depend on a distinct port, preventing accidental
command-family mixing.

`daimon-local-daemon` publishes a new Unix socket at mode 0600, applies finite
read/write deadlines and request-count limits, authenticates host facts before
opening a service session, and binds each request to the connection session rather
than trusting a client handle. A substituted handle is refused before service
dispatch. Failure to write a post-dispatch reply is outcome unknown, not evidence
that execution did not occur. Teardown removes the path only when it still names
the exact socket inode created by the daemon. This profile deliberately leaves
the peer-credential authentication policy to the embedding executable.

