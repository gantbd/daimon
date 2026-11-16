# ACP provider qualification

Status: evidence recorded 2026-11-16. These are bounded compatibility gates,
not claims of provider feature parity or full production readiness.

The baseline opt-in `daimon-acp` live gate sends only ACP `initialize`,
`session/new`, and, when advertised, `session/close`. For a deployment-selected
agent-handled method it also sends one `authenticate` request after initialize
and before session creation. It never invokes a terminal authentication method
on the ACP connection. It does not submit a model prompt. A separately gated
test submits one bounded no-tool prompt. The hermetic
process fixture separately qualifies bounded streaming, cooperative
advance, exact permission correlation, cancellation while a prompt remains
pending, silent live turns, and verified ambient-context projection. It also
pins ACP v1 capability semantics: `loadSession: false` and null lifecycle
markers remain false; true and object lifecycle markers are retained; and
modes/legacy models require a structured `session/new` state whose current
identity occurs in its advertised set. Empty or misplaced setup objects remain
false. Separate gates reject missing JSON-RPC versions,
invalid identities, mixed result/error responses, malformed errors, and method
envelopes carrying response fields before ACP dispatch. Unexpected response
identities during initialize or a pending prompt fence the operation as unknown
instead of being answered or skipped in favor of a later convenient response.
The stream gate also injects a foreign-session update and an update carrying a
request ID; both fence the turn before the text can enter durable event history.
A non-text content block carrying an extra `text` field is ignored as unsupported
and cannot masquerade as an assistant message.
Malformed structured updates are likewise withheld: a tool call without its ACP
identity and a plan whose entries are not an array produce no tool/plan evidence.

| Provider path | Qualified version | Result | Evidence boundary |
| --- | --- | --- | --- |
| `codex-acp` | `@agentclientprotocol/codex-acp 2.6.0` | Current ACP v1 TCK and Daimon adapter gates passed | A disposable, integrity-pinned 2.6.0 install negotiated ACP v1 on 2026-11-16. Upstream `acp-tck` 0.3.0 returned a conformant verdict with all 32 mandatory and all 19 exercised advertised-capability requirements passing. Daimon's independent adapter gates then passed initialize/session-create/close, one bounded no-tool prompt with nonempty assistant output and completed terminal evidence, one typed permission challenge resolved only through its exact `RejectOnce` option, and genuine fresh-process restart/reattach after one explicitly authorized no-tool seed turn with zero history replay. The target remained absent and no capability was granted. The isolated home contained only an auth-file symlink plus an in-memory model/reasoning pin; neither the global package nor active user configuration was changed. The TCK's three advisory requirement failures and one informational shutdown-timing failure are retained below as explicit non-claims. |
| `codex-acp` historical baseline | `@agentclientprotocol/codex-acp 1.8.0` | Daimon gates passed; upstream TCK did not conform | The installed 1.8.0 bridge passed the same Daimon lifecycle, prompt, and reject-once permission paths. The pinned upstream TCK nevertheless failed two advertised capability requirements, `ACP-DELETE-001` and `ACP-RESUME-001`, so this version is historical adapter evidence rather than the recommended qualified provider floor. Earlier 0.10.0 prompt evidence is older still. |
| `gemini --acp` | Gemini CLI `0.68.0` | Consumer-OAuth entitlement blocked after initialize | Rechecked 2026-11-16: the current no-prompt adapter gate still reached `OutcomeUnknown` during open before session admission. The host selects `oauth-personal`, with no Gemini API-key or Google Cloud project variable present, and the preceding raw provider evidence was `UNSUPPORTED_CLIENT` after successful ACP v1 initialize. Inspection of the installed 0.68.0 path shows `session/new` calls `refreshAuth` before it examines the client's filesystem capability, and maps that exception to JSON-RPC `-32000`; this is not evidence of an ACP client-capability mismatch. Google's [official transition notice](https://github.com/google-gemini/gemini-cli/discussions/28017) says Gemini CLI stopped serving individual free, Google AI Pro, and Google AI Ultra accounts on 2026-06-18 while enterprise licenses and API-key authentication remain supported. No prompt was sent. Gemini remains unqualified on this host until an explicitly selected supported credential lane is exercised. |
| Claude ACP bridge | Claude Code `2.1.311`; no bridge installed | Not applicable as ACP; separate transport passed | The installed `claude` command exposes no native ACP mode and no separate `claude-agent-acp` command is present. Its documented bidirectional `stream-json` Agent SDK transport now has the separate `daimon-claude` adapter, which passed a genuine no-prompt initialize/close gate; see [`claude-provider-qualification.md`](claude-provider-qualification.md). It is not presented as ACP. |

Re-run an installed provider explicitly:

```sh
DAIMON_ACP_PROGRAM=/absolute/provider/path \
DAIMON_ACP_ENV='HOME PATH PROVIDER_SPECIFIC_NAME' \
  cargo test -p daimon-acp --test live_provider -- --ignored --nocapture
```

Add `DAIMON_ACP_ARGS='--acp'` for a command whose ACP mode is selected by
arguments. If initialize advertises an agent-handled authentication method, set
its exact identifier with `DAIMON_ACP_AUTH_METHOD`; the gate refuses missing,
duplicate, or terminal descriptors before session creation. Terminal-method
commands remain an operator/deployment concern and are never executed by this
adapter. Credentials, login state, executable paths, and environment values
remain deployment configuration and are never retained in protocol values or
checkpoints. `DAIMON_ACP_ENV` defaults to `HOME PATH`; add only names required
by the selected provider. The generic gate does not pre-authorize Codex, Gemini,
Google, and Anthropic credentials into the same child.

For Gemini's native ACP mode, the named no-prompt target fixes `--acp` and the
credential-name allowlist while leaving credential values host-only:

```sh
DAIMON_GEMINI_PROGRAM=/absolute/path/to/gemini \
DAIMON_GEMINI_ENV='HOME PATH GEMINI_API_KEY' \
  make qualify-gemini-transport
```

Use `GOOGLE_API_KEY` or the documented Google Cloud project/location variables
instead when that is the deliberately selected supported lane. The target does
not fall back from an entitlement or authentication refusal.

Claude Code's official [CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-usage)
and Agent SDK documentation describe `--input-format stream-json` with
`--output-format stream-json` for a long-lived bidirectional session. That is a
viable provider-neutral Daimon transport, but not an ACP dialect.
`daimon-claude` now freezes its launch profile, parses a bounded closed subset
of message/control envelopes, and projects exact host permission requests. Its
credential-free process gate is complete, and installed Claude Code `2.1.311`
has passed the genuine no-prompt initialize/close gate. A bounded no-tool prompt
gate exists behind `DAIMON_CLAUDE_ENABLE_PROMPT=1`. Its 2026-11-16 run reached
the installed provider and received assistant output, but the terminal result
combined `subtype="success"` with `is_error=true` and no errors. Daimon retained
failure and the completion gate did not pass. Live-model completion and recovery
qualification therefore remain open.

An installed bridge may lag the Codex configuration or model-catalog schema.
That is deployment incompatibility, not an ACP dialect result. Qualify such a
bridge with a dedicated configuration home and explicit model selection; do
not rewrite the user's active Codex configuration as part of the gate.

The separately gated no-tool prompt spends one provider turn, never approves a
permission, and requires nonempty assistant output plus a completed terminal
event:

```sh
DAIMON_ACP_ENABLE_PROMPT=1 \
DAIMON_ACP_PROGRAM=/absolute/provider/path \
DAIMON_ACP_ENV='HOME PATH CODEX_HOME' \
  cargo test -p daimon-acp --test live_provider \
  genuine_provider_completes_one_no_tool_prompt -- --ignored --exact --nocapture
```

The genuine-provider restart gate uses one explicitly authorized bounded
no-tool seed turn because Codex does not retain an empty thread across process
exit. It then drops the first adapter process while the provider session is
idle, launches a fresh process, requires advertised resume plus a bounded
recovery locator, and accepts only an explicit `session/resume` that returns
Ready with zero replayed events or implicit prompt activity:

```sh
DAIMON_ACP_ENABLE_REATTACH=1 \
DAIMON_ACP_ENABLE_REATTACH_PROMPT=1 \
DAIMON_ACP_PROGRAM=/absolute/provider/path \
DAIMON_ACP_ENV='HOME PATH CODEX_HOME' \
  make qualify-acp-reattach-live
```

Use a bridge version whose upstream resume requirement has passed. The installed
historical Codex ACP 1.8.0 is intentionally not such evidence.
An isolated 2.6.0 no-prompt probe on 2026-11-16 confirmed why the seed is
necessary without spending a model turn: the first process created an empty,
non-ephemeral thread, but after process exit the fresh app server rejected
`thread/resume` with `no rollout found`. Daimon surfaced only `OutcomeUnknown`.
No fallback `session/new`, `session/load`, prompt, or retry occurred. The
explicit-spend gate above subsequently passed against the same pinned 2.6.0
bridge using the existing authenticated Codex session and no API key. After one
fixed no-tool seed turn, Daimon dropped the first provider process, launched a
fresh process, performed only explicit `session/resume`, returned the canonical
session to Ready with the same recovery locator, and observed zero replayed
events. The reviewed normalized shell capture is retained at
[`evidence/codex-acp-2.6.0-reattach-2026-11-16.txt`](evidence/codex-acp-2.6.0-reattach-2026-11-16.txt).
A matching hermetic regression makes that boundary permanent: its provider
returns the same `no rollout found` error for `session/resume` and exits if the
adapter attempts `session/new`; Daimon returns only `OutcomeUnknown` without a
history-load or prompt path.

The separate reject-only permission gate must run in an approval-requesting
provider mode. It never selects an allow option:

```sh
DAIMON_ACP_ENABLE_PERMISSION_PROMPT=1 \
DAIMON_ACP_PROGRAM=/absolute/provider/path \
DAIMON_ACP_ENV='HOME PATH CODEX_HOME CODEX_CONFIG INITIAL_AGENT_MODE' \
INITIAL_AGENT_MODE=read-only \
  make qualify-acp-permission-live
```

Hermetic ACP process gates now cover post-dispatch provider exit as
outcome-unknown without an `Advance` relaunch. They also prove that stale
permission request and option identities do not consume the retained valid
challenge, child environment is cleared before an exact name allowlist is
copied, and launch diagnostics expose neither arguments nor environment names.
If provider completion wins a cancellation race, the ACP adapter preserves the
completed disposition rather than manufacturing cancellation evidence; the
service's cancellation receipt validator then fences that operation.
The adapter also negotiates through the shared digest-bound macOS Seatbelt
launcher under a deny-default fixture policy. The mechanism gate independently
proves file mutation is denied; it does not certify a deployment's policy.

Still open before a production claim: a non-macOS sandbox backend and reviewed
provider-specific Seatbelt policy, authenticated Gemini session creation through
an explicitly selected supported API-key or enterprise lane, Claude live-model
qualification, prompt and permission journeys for the other providers,
a live mixed-provider prompt ensemble, and disposition of the TCK advisory and
informational findings. The upstream experimental ACP compatibility kit has now
been executed against both Codex bridge versions; its bounded evidence is below.
The hermetic mixed-transport composition is qualified by
`make qualify-agent-router` using ACP and Claude fixture processes. On
2026-11-16, `make qualify-agent-router-live` additionally passed no-prompt
initialize/open/close against installed `codex-acp` 1.8.0 and Claude Code
2.1.311 behind one profile-selected provider-neutral router. It is transport
composition evidence, not mixed model-output evidence.

## Upstream agent TCK

The upstream `agentclientprotocol/acp-tck` is an experimental compatibility kit
for ACP **agents**. It launches the selected agent directly and exercises
initialize, session lifecycle, prompt turns, permissions, cancellation, error
handling, and transport hygiene. It therefore complements the `daimon-acp`
client-adapter gates above; it cannot establish that Daimon's client projection
is correct, and its own documentation says its verdict is not an official
conformance statement.

The gate is deliberately absent from `make check`: the TCK sends model prompts
and can exercise tools. Install it from a pinned release tag or commit as
recommended upstream, choose a scratch workspace and report path, and opt in
explicitly:

```sh
DAIMON_ACP_TCK_ENABLE_MODEL_SPEND=1 \
DAIMON_ACP_TCK=/absolute/path/to/pinned/acp-tck \
DAIMON_ACP_TCK_WORKSPACE=/absolute/path/to/empty-scratch \
DAIMON_ACP_TCK_REPORT=/absolute/path/to/report.json \
DAIMON_ACP_PROGRAM=/absolute/path/to/provider \
DAIMON_ACP_ARGS='--acp' \
  make qualify-acp-tck
```

The TCK exit status remains authoritative. Preserve its JSON report because it
pins the TCK/schema versions, requirement outcomes, diagnostics, and whether a
run was blocked by authentication or version mismatch. Reports can contain wire
transcripts and stderr, so they are operator evidence rather than repository
fixtures unless reviewed and redacted.

The 2026-11-16 comparison pinned `acp-tck` v0.3.0 at commit
`f050441441ca4faafd1d4e58761125304d06743d` and ACP schema revision
`3961af94fa62d2386d993cadf1afc8b146fc799a`. Both runs used protocol v1, an
isolated scratch workspace and configuration home, the same read-only launch
mode, and logout disabled:

- Codex ACP 1.8.0 completed all 124 tests but returned a non-conformant verdict:
  mandatory 32 pass/0 fail; exercised advertised capabilities 13 pass/2 fail.
  `ACP-DELETE-001` and `ACP-RESUME-001` failed because the bridge advertised
  those lifecycle methods but could not delete or resume the created session.
  Eight additional advisory requirement failures did not determine the verdict.
- Codex ACP 2.6.0 returned a conformant verdict: mandatory 32 pass/0 fail;
  exercised advertised capabilities 19 pass/0 fail. Three advisory requirements
  remain failed (`ACP-ERROR-004`, `ACP-LIST-003`, and `ACP-SCHEMA-002`), as does
  informational `ACP-SHUTDOWN-001`; these do not determine TCK conformance.

This establishes a qualified bridge-version floor for the tested profile, not
general production readiness or an official ACP certification. Authentication
was already present, permission-provoking coverage remains stronger in Daimon's
separate reject-only gate, logout was intentionally not exercised, and
unadvertised or unobserved capabilities remain outside the claim. Full reports
contain provider transcripts and are retained only as temporary operator
evidence; this document records the reviewed bounded summary.

The TCK's direct `session/resume` result does not by itself qualify Daimon daemon
recovery. ACP v1 distinguishes resume without history replay from `session/load`
with replay. Daimon's selected design uses only resume for an idle retained
session, behind an explicit durably fenced `Reattach` command with fresh
authority and attempt checks; it forbids automatic startup resume and leaves an
active turn outcome-unknown. The canonical design is in
[`specification.md`](../specification.md#provider-binding-recovery). Its
checkpoint, service and adapter gates now pass, and the real
`daimon-local-agent` executable is killed and reopened around a live hermetic
resume-capable ACP child before an explicit reattach and new prompt. The
separate genuine Codex 2.6.0 gate now proves the corresponding fresh-provider-
process resume boundary after one authorized seed turn.

## Client-operation boundary

The V1 adapter keeps ACP client filesystem writes unavailable. Filesystem reads
and terminals remain unavailable by default. Reads are advertised only when a
host-owned `AgentClientFileReader` affirms the exact frozen open binding. A
hermetic process gate proves the enabled path preserves
the canonical Daimon session, turn, workspace and execution/attempt evidence;
accepts only an absolute ACP request with valid line bounds; returns bounded
UTF-8; and emits a safe relative path plus verified SHA-256 digest and byte
count as a canonical `FileRead` event. The default attenuation gate continues
to prove all three capabilities are false when that port is absent.

`daimon-local-agent` now installs that port only for an explicit workspace
`acp_file_read` scope whose capability is part of the application-issued grant.
Configuration qualification canonicalizes workspace-relative roots and rejects
symlink escape. At callback time the production governor uses the continuation's
logical time to reauthorize the exact execution through the same session-bound
Aegis client, revalidates the exact current Chronos attempt, canonicalizes the
absolute request into the allowed workspace roots, and returns bounded UTF-8.
The real-process journey crosses actual Aegis, Chronos, Daimon and ACP processes,
then reopens the digest-bearing read event from durable storage. Provider-native
tools can bypass an ACP client callback, so the port is not a process sandbox;
deployment isolation remains a separate control. Permission UI alone is not
filesystem authority.

The adapter also has a host-owned `AgentClientTerminal` lifecycle port matching
ACP v1 `terminal/create`, `output`, `wait_for_exit`, `kill`, and `release`.
Capability advertisement is false unless the port affirms the exact frozen open
binding. Create carries the canonical session, turn, workspace, execution and
continuation logical time; subsequent operations are restricted to the opaque
session-owned handle. Wait is polled without blocking the provider transport,
create is rolled back if its response cannot be delivered, and cancel, close or
provider-owner loss releases every session handle. A hermetic process gate covers
the complete lifecycle, typed signal-string exit status, bounded UTF-8 output
evidence and cancel cleanup. This is not a universal execution claim:
`daimon-local-agent` advertises terminals only for an explicit workspace scope
and granted capability. Its production governor canonicalizes the boundary,
workspace and absolute command registry; enforces approved argv prefixes, cwd
containment, environment-name allowlisting and bounded handles/output; rejects
known eval/interpreter escape flags; and reruns current Aegis authority plus the
exact Chronos attempt at create time. The independent
`daimon-process-boundary` mechanism gate proves bounded pipe output, normal reap,
and owner-pipe-loss cleanup of both a direct child and spawned descendant. Its
`daimon-process` manager additionally proves absolute-executable and clean-env
admission, output-credit ownership, UTF-8 suffix truncation, nonblocking exit
polling, redacted diagnostics, and cancellation only after cleanup. This layer
is containment, not authority. Agent permission presentation is not command
authority. `make qualify-local-agent` runs both the governed-read journey and a
second real-process terminal journey through Aegis, Chronos, ACP, the boundary,
durable event storage and daemon restart. Broader command-policy review and
non-macOS isolation remain deployment concerns.
