# Traceability ledger

| Requirement | Planned implementation | Current evidence | Status |
| --- | --- | --- | --- |
| D1 external work | request-only protocol | native command excludes provider receipt and selected provider remains a trusted host port | Satisfied for volatile service profile |
| D2 identity | fixed-width IDs and authority-free exact task-attempt reference | preparation/provider receipt scenarios plus bounded public-client Chronos registry and real running-attempt service journey | Satisfied for selected Chronos mapping; deployment registry provisioning remains operational policy |
| D3 budgets | `ExecutionBudgetV1`, profile ceilings, pre-publication validation | core token/context/output/proposal checks, bounded codecs, mandatory provider usage and bounded HTTP response | Partial; wall-clock cancellation remains open |
| D4 tools | authority evidence finite tool set and request subset check | unauthorized tool and expired authority BDD; public Aegis profile/tool decisions; epoch revocation blocks retained delivery without redispatch | Satisfied for selected public Aegis adapter; deployment identity registry and secret/tool runtime remain open |
| D5 outcomes | closed disposition and attributed provider receipt | completion/replay plus commit-before-provider unknown fence, commit-before-publication result, indeterminate commit, exact reopen and discarded-reply process recovery through Moira under live Aegis/Chronos composition | Partial; cancellation races open |
| D6 idempotency | retained request/result maps keyed by fixed idempotency/execution IDs | matching model replay after service restore plus conflict BDD; marker commits fence provider admission; composed Moira journey proves one Chronos validation/provider call, one Agora message and one Vellum edit across reply loss and proposal-store reopen | Satisfied for selected local public-client federation; independent process termination at every peer boundary remains open |
| D7 provenance | bounded result evidence | exact provider-document, message, context/source/grounding, token and evidence-digest retention; digest changes on message/context/profile drift; canonical checkpoint recovery; the opt-in live loopback gate receives nonempty output and provider-reported usage from an installed Ollama model while preserving exact profile/evidence attribution | Satisfied for selected terminal model profile, including live provider-adapter smoke |
| D8 isolation | dependency-free deterministic core with provider adapters outside | dependency closure gate; OpenAI and Dendrite dependencies remain adapter-only | Satisfied for selected adapters |
| D9 shutdown | retained execution ownership | canonical receipt-gated checkpoint and exclusive local directory retain unknown/completed phases; fresh daemon processes reopen the exact result after a discarded reply without redispatch | Satisfied for selected local process profile; signal/cancellation policy open |
| D10 public boundary | protocol/client DTOs plus trusted authority, attempt, provider and store ports | dependency-closure gates; facade, replay, live Aegis revocation, real Chronos running-attempt validation, composed Moira/Aegis/Chronos/Daimon execution with discarded reply, daemon reopen and reauthorization, canonical/truncation/mutation refusal, session substitution refusal and real private-socket reopen | Satisfied through native wire, authenticated local daemon, exclusive persistence and public-client Aegis/Chronos adapters |
| D11 frozen provider selection | credential-free canonical profile digest | endpoint/model/policy drift rejection; bearer rotation leaves digest unchanged; receipt digest binding; one actual `gemma3:27b` Ollama completion retains the exact frozen profile digest | Satisfied for loopback OpenAI-compatible profile |
| D12 exact grounding | Dendrite `query_surface` plus exact `read_ref` verification | canonical surface and authority digest tests; drift refusal; real bounded loopback MCP Streamable HTTP/chunked-SSE journey; optional executable configuration | Satisfied for selected Dendrite transport profile |
| D13 proposal sovereignty | typed output proposals only | strict schema adapter, bounded core/wire/checkpoint result, Moira projection into distinct ordered effects, durable uncertainty fence and lookup-only reconciliation; no Agora/Vellum dependency in Daimon | Satisfied for selected local public-client federation; multi-process kill matrix open |
| D14 interactive-agent separation | independent canonical session family and provider-specific adapters outside the core | durable service/wire/checkpoint gates; dedicated authenticated private Unix endpoint plus matching client, session-substitution refusal and lost-reply uncertainty gate; ACP adapter, historical Codex 1.8.0 lifecycle/prompt/permission evidence, and current 2.6.0 lifecycle/prompt/permission/fresh-process reattach plus pinned upstream ACP v1 TCK conformance; configured ACP agent-handled authentication is launch-digest bound, occurs once before session creation, carries no credentials, and refuses missing, duplicate, or terminal method descriptors; distinct Claude stream-JSON discriminator roundtrip, hermetic progress/context/permission/cancellation/uncertainty gates, installed Claude `2.1.311` no-prompt initialize/close gate, explicit-spend Claude prompt gate, and a guarded pinned upstream ACP agent-TCK target; both process adapters classify exit after prompt dispatch as outcome-unknown without relaunch, refuse stale permission request/option identities without consuming the retained valid challenge, clear the child environment before copying an exact allowlist, redact launch arguments plus environment names from diagnostics, and preserve uncertainty/correct disposition when provider completion races cancellation; ACP client filesystem reads are default-off and enabled only through a host port that receives the exact canonical session/turn/workspace/execution and continuation-time binding, validates bounded UTF-8/digest receipts and emits canonical `FileRead` evidence; writes remain unavailable; a separate default-off terminal host port carries the same exact create-time binding and hermetically qualifies create/output/deferred-wait/kill/release plus cancellation cleanup; the independent Daimon pipe-mode process-group sidecar proves bounded framed output, normal reap and owner-loss cleanup of a direct child plus descendant, while its synchronous sole-writer manager proves absolute executable/clean-env admission, UTF-8 suffix bounds, nonblocking exit polling and cleanup-complete cancellation; the production local-agent terminal scope canonicalizes its boundary, workspace and absolute command registry, assigns each command an independently checked tool capability (with a scope default only for compatibility), enforces approved argv prefixes, cwd containment, clean allowlisted environment names and fresh Aegis/Chronos create admission, and crosses the real boundary before durable terminal evidence is reopened; the production local-agent read scope canonicalizes configured roots, rejects symlink escape, shares its session-bound Aegis and current-attempt Chronos guards with the service, and crosses those real peers before durable read evidence is reopened; shared macOS Seatbelt launch retains bounded digest-verified policy bytes, includes isolation identity in the frozen profile, blocks file mutation under a deny-default mechanism gate and carries both adapters through negotiation; bounded profile-digest router with pre-dispatch session fencing, alias refusal, a concurrent real-process ACP/Claude composition gate, and an explicit-spend Claude-first/Codex-second no-tool prompt gate with distinct persona markers and frozen-profile evidence; strict local-agent application derives launch identity, issues an exact session-local Aegis profile/tool grant, validates Chronos attempts, assembles bounded exact context, owns the exclusive durable checkpoint and dedicated authenticated socket, and its executable process gates run the ACP child under the digest-bound deny-default policy, prove the forbidden workspace write is denied, complete open/prompt/close, and reopen exact read or terminal evidence after daemon termination without provider redispatch | Partial; the Pantheon and bounded-web gateway programs and their live denial receipts remain open, as do non-macOS isolation and deployment command-policy review, completed Claude live-model turns, Gemini session admission through an explicitly selected supported API-key or enterprise lane, disposition of remaining TCK non-verdict findings, and a live mixed-provider ensemble |

The current D14 Codex gates passed on 2026-11-16 against a disposable
`@agentclientprotocol/codex-acp` 2.6.0 install: initialize, session creation,
nonempty assistant output, completed terminal evidence and close all succeeded
through an isolated configuration home. The same version returned conformant
from pinned `acp-tck` v0.3.0 with 32/32 mandatory and 19/19 exercised advertised
capability requirements passing. The installed 1.8.0 bridge retains historical
Daimon adapter evidence but failed the TCK's advertised delete and resume
requirements. Hermetic Daimon executable restart, the integrated Moira-driven
process-kill/reattach journey, and a genuine pinned Codex 2.6.0 restart all pass.
The genuine gate used one explicitly authorized no-tool seed turn, then resumed
through a fresh provider process with the same recovery locator and zero history
replay. Its reviewed shell capture is retained with the provider evidence.

The current Codex permission gate also passed on 2026-11-16 in the 2.6.0 bridge's
read-only approval mode. A typed challenge retained the exact turn and bounded
options; Daimon selected only `RejectOnce`, granted no capability, received a
matching terminal event, and verified the predeclared nonexistent target stayed
absent. This is independent of the upstream TCK's direct agent verdict.

The D14 live router gate also passed on 2026-11-16 against installed Codex ACP
and Claude stream-JSON processes. Both sessions opened concurrently with their
distinct frozen profile digests and closed through the routes fenced before
dispatch. It sent no prompt, so live mixed transport composition is proven while
mixed-provider model output remains open. The separately opt-in live ensemble
gate now requires one completed no-tool persona turn per route, rejects tool or
permission evidence, and verifies distinct frozen profile attribution. It runs
Claude first so a login failure cannot spend a Codex turn.

The D14 Claude prompt gate was executed on 2026-11-16. It received nonempty
assistant output, then retained failure for the provider's terminal
`subtype="success", is_error=true, errors=[]` envelope. Thus the table's open
Claude item now means a *completed* live prompt, not that the gate has never
been attempted; provider text alone is not completion evidence.
An additional run explicitly selected the installed `sonnet` alias but yielded
no terminal result within the complete 120-second budget. Daimon retained the
active turn through the bound, and the gate failed without promoting elapsed
time or model selection into completion evidence. A later captured retry failed
in 3.42 seconds with provider-state `authentication_failed`; the installed
CLI's own status reports that its OAuth session is logged out. The reviewed
failure capture is retained, and completed Claude output remains open until the
operator refreshes that login.

D14 capability evidence additionally checks the current ACP v1 value rules
against a real fixture process. A boolean false `loadSession`, null lifecycle
markers, and null setup mode/model state remain false. Boolean true and object
life-cycle markers survive, while mode/legacy-model availability requires a
structured `session/new` state with a current identity in its advertised set.
Presence or an empty object alone cannot cause Daimon or Moira to overstate a
provider feature.

The same D14 gate validates each inbound line as one JSON-RPC 2.0 object before
method dispatch. Missing/wrong versions, non-integral identities, absent or
mixed response arms, malformed errors, and method envelopes carrying response
fields are refused; real fixture processes prove malformed initialize replies
cannot open a Daimon session. Unexpected response correlation during initialize
or a prompt also becomes outcome-unknown, and the client never replies to a
response as though it were an unsupported request.
Session-update qualification additionally rejects both a notification naming a
foreign remote session and a request-shaped update carrying an ID. Neither can
cross into the cursor-ordered event history used by Moira. Content projection
also requires the ACP `text` discriminator; a non-text block with an extension
field named `text` is not retyped as assistant evidence.
Tool/plan projection separately requires a tool-call identity (and title for a
new call) or a plan entries array, so malformed structured updates remain absent
from Moira's retained evidence.

