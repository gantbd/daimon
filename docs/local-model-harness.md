# Local model harness profile

Status: selected V1 contract and local adapter slice implemented

## Decision

Daimon owns provider-neutral, bounded model execution. The first selected wire
profile is OpenAI-compatible chat completions over a composition-selected local
endpoint. Ollama, LM Studio and llama.cpp deployments are provider profiles, not
separate engine semantics when they expose that same wire contract.

Provider selection is frozen before execution as a canonical, credential-free
profile snapshot. The snapshot binds the provider profile, Daimon harness
profile, wire profile, model, declared structured-tool support and the digest of
the complete non-secret profile document. Endpoint admission, health checks,
credentials and loopback policy remain trusted service-composition concerns.
The engine refuses a completion whose profile digest differs from the prepared
invocation. A health check does not authorize execution and is never completion
evidence.

The selected V1 execution is terminal and non-streaming. HTTP libraries must
not perform implicit retries. A transport failure after request admission is
outcome-unknown until reconciled; neither the provider adapter nor Daimon may
silently redispatch it. Provider fallback is a new Moira-owned effect with a new
identity, not an adapter retry.

Sampling temperature is explicit non-secret profile policy, represented in
thousandths from 0 through 2000, included in the canonical profile digest and
sent on every provider request. Methodical qualification uses zero; a creative
persona may select a nonzero value, but it must do so in a new frozen profile
rather than inherit a mutable provider default.

## Context and grounding

Every context item is named by a request reference and materialized by an
authorized outbound adapter. The prepared model invocation requires the exact
set of requested references, rejects duplicates and enforces the aggregate
context-byte and estimated-input-token budgets.

Dendrite is an optional grounding source. A Dendrite context item carries the
authored depth, exact grounding digest and exact projected-surface digest. The
Dendrite adapter must verify returned bytes against those identities before it
constructs `ContextEvidenceV1`; human-readable MCP display text is not routing
or integrity evidence. Dendrite remains consumer-neutral and receives no
Daimon execution, provider, Chronos attempt or checkpoint identity. Daimon can
start without Dendrite; only an invocation that explicitly requires unavailable
grounding refuses.

## Results and peer effects

A model completion returns bounded output, observed token use, an attributed
evidence digest and typed proposals. Proposal families are an Agora message
proposal, a Vellum expected-revision edit proposal, and a provider-native tool
call bound to its requested capability. They are not peer-effect
receipts. Moira decides whether to submit them through the owning engines'
public clients and retains the resulting success, refusal or uncertainty as
separate saga effects. Daimon never completes a Chronos task, publishes an
Agora message or mutates a Vellum document directly.

Structured tools are enabled only for frozen profiles that explicitly support
them and only for capabilities present in the invocation. OpenAI-compatible
function definitions use opaque capability-derived names; returned call IDs are
bound to the execution and become fixed request identities. Arguments must be a
JSON object and are canonicalized. Text that resembles a call remains text.
Daimon emits a proposal, never a tool receipt; Moira supplies the policy budget
and admits each call as its own authorized continuation effect.
The runnable `daimon-local-model` configuration exposes this as the closed
`provider.structured_tools` Boolean; it defaults false and enters the canonical
provider-profile digest. Enabling it advertises wire capability only—each
invocation still needs bounded requested capabilities and every resulting call
still requires Moira-owned authorization and continuation handling.

Ollama's non-streaming OpenAI-compatible response includes an additive `index`
on each native tool call. The selected decoder accepts that bounded field while
continuing to reject unknown call/function members; the index is transport
metadata and does not enter Daimon's stable request identity. Live qualification
with `qwen3:32b` discovered and now covers this provider behavior through Moira's
full authorized continuation path.

## Prior art applied

Axon supplies failure history for wire-shaped provider adapters, boot-time
health selection, disabled implicit retries, credential-free frozen profile
snapshots, structured tool calls, usage capture and content-addressed evidence.
It is not a Daimon dependency.

Dendrite supplies the consumer-neutral, bounded, digest-identified grounding
surface. Its exact-byte verification and real subprocess-termination history
inform the adapter and future tool-process profiles. The public Dendrite
contract may be consumed by an independently qualified Daimon adapter.

## Qualification order

1. Deterministic core tests for exact context, profile binding, budgets, typed
   proposals, matching replay and conflicting receipts.
2. Protocol, checkpoint and wire promotion with canonical bounded codecs.
3. OpenAI-compatible adapter tests through a real HTTP codec path and injected
   local test server; no live provider in ordinary unit tests. The opt-in
   `make qualify-openai-live DAIMON_OPENAI_LIVE_MODEL=...` gate sends one bounded,
   non-retried request to an already-running loopback provider and requires
   nonempty output, observed usage, exact frozen-profile attribution and no
   invented peer proposals.
4. Optional Dendrite adapter and loopback MCP transport tests for structured
   routing, chunked SSE, exact-byte digest verification, absence and drift.
5. Local-daemon restart qualification proving one provider admission across a
   lost reply and reopen.
6. Moira-owned Agora -> Chronos -> Daimon -> Vellum/Agora saga qualification,
   including reply loss at every effect boundary and no duplicate peer effect.

Items 1–4 are implemented. Model protocol, wire, durable checkpoint, client and
dedicated authenticated Unix-daemon families are additive and cannot be decoded
as legacy frames. Ordinary replies retain their original wire kind; replies with
native calls use an additive model-reply kind, and durable invocations use the
`DAIMONM4` checkpoint. Native calls retain their bounded provider correlation
identifier so a later tool-result turn can use the provider's real matching
contract; the preceding additive wire family remains decodable but is not
resumable. Resumed invocations bind the source execution, original assistant
output, exact call arguments, provider correlation, tool evidence/output
digests, and output bytes. The loopback provider has real HTTP codec tests, mandatory
usage accounting, strict JSON-schema proposal mode, native structured-call tests,
and a canonical credential-free profile digest. The Dendrite adapter verifies both `read_ref` authority bytes and
the canonical `query_surface` projection; its selected live client performs
bounded loopback MCP Streamable HTTP calls and parses structured chunked-SSE
results without retry. Item 5 is proven at the service/store
seams and remains open as one combined model-daemon process-loss qualification.
Item 6 is now connected through Moira's Daimon and durable Vellum public-client
adapters. Moira assigns one effect per proposal, persists the ordered and
uncertainty-fenced frontier in a separately owned SQLite store, and exposes it
through a representation-independent service/client contract. The remaining
closure is the combined Agora -> Chronos -> Daimon -> Agora/Vellum process
qualification. The selected local public-client journey now proves reply-loss
recovery and no duplicate provider, Agora or Vellum effect across proposal-store
reopen. A separate Moira-owned chatbot gate now crosses the actual private
Daimon wire and this OpenAI-compatible adapter against installed Ollama
`gemma3:27b`, then publishes through actual Agora and Vellum daemons. That is
first-execution evidence, not the full `daimon-local-model` Aegis/Chronos
composition or a process-loss proof; independent termination at every boundary
remains open.

## Delivery plan

The implementation sequence deliberately keeps ownership seams visible:

1. **Local execution substrate (implemented).** Provider-neutral Daimon core,
   OpenAI-compatible loopback adapter, exact profile/context binding, bounded
   model wire, durable checkpoint and authenticated model socket.
2. **Optional grounding (implemented).** Digest-verified Dendrite client port,
   context assembler and bounded loopback MCP Streamable HTTP transport. It
   remains an optional adapter and never becomes a core dependency.
3. **Federated proposal saga (implemented through native service).** Daimon
   results become typed proposals; Moira allocates distinct Agora/Vellum effect
   identities, orders them, persists receipts/fences and exposes typed replay.
4. **Runnable composition (implemented).** A small composition executable loads one
   credential-free local profile plus secret material from the host, opens the
   durable Daimon and Moira stores, binds their private sockets and injects Aegis,
   Chronos and optional Dendrite public clients. It owns configuration only.
5. **Process qualification (next).** Kill/reopen after every committed request
   and before every reply across Agora ingress, Chronos admission, Daimon model
   execution, Agora publication and Vellum edit. Assert one provider request and
   one peer mutation per stable effect identity.
6. **Tool continuation boundary (implemented).** Native
   structured calls are capability-bound typed proposals, survive wire and
   checkpoint recovery, and cross the Daimon-to-Moira adapter without textual
   inference. Moira admits them through its separately authorized, budgeted and
   recoverable continuation contract. Tool output is durably retained before
   settlement and resumes through the private wire/daemon using native assistant
   tool-call plus matching tool-result messages. Multi-turn process-loss
   qualification remains open.

