# Claude stream-JSON provider qualification

Status: credential-free hermetic and installed-provider transport evidence
recorded through 2026-11-16. Installed Claude Code `2.1.311` passed initialize
and close. The bounded live-model gate reached the provider and emitted
nonempty assistant output, but its terminal envelope was
`subtype="success", is_error=true, errors=[]`; Daimon correctly retained a
failed disposition rather than promoting assistant text to completion. The
provider therefore remains unqualified for completed live turns on this host.
An additional 2026-11-16 run explicitly pinned the installed `sonnet` alias.
That run produced no terminal result within the declared 120-second session
budget, so the gate exhausted its independent polling fuel and failed without
claiming completion. The explicit model pin therefore demonstrates a second
honest failure mode rather than overwriting the earlier terminal evidence.

Claude Code's Agent SDK uses a long-lived bidirectional NDJSON/control channel.
It is represented by `AgentWireProfileV1::ClaudeAgentStreamJson` and the
`daimon-claude` adapter, never by the ACP discriminator. The adapter follows the
official SDK process shape: stream-JSON input/output, verbose structured output,
the stdio permission prompt tool, an explicit `initialize` control request,
correlated control responses and user messages marked `client_composed`.

The hermetic process qualification proves:

- exact mandatory transport argv and exact configured working directory;
- a cleared environment plus the single adapter-owned session-state flag;
- bounded line framing, background stdout ownership and multi-slice progress;
- typed text, tool, usage and terminal projection with contiguous cursors;
- bounded Agora/Chronos/Vellum/Dendrite context envelopes delivered verbatim;
- deterministic `can_use_tool` request and option identities;
- `AllowOnce` with the exact original structured input and `RejectOnce` without
  persistent permission mutation;
- cancellation only after a correlated interrupt acknowledgement and terminal
  result, including denial of a permission request already blocking the turn;
- local child teardown on close; and
- malformed or unknown provider envelopes returning `OutcomeUnknown` without an
  implicit retry.

Run the credential-free gate:

```sh
DAIMON_CLAUDE_MUST_NOT_LEAK=secret \
  cargo test -p daimon-claude --test claude_process
```

The sentinel is intentionally present in the test runner and absent in the
child, proving that ambient environment values are not inherited. Real
credentials, login state, program paths and any selected model remain deployment
configuration and do not enter protocol values or checkpoints.

Run the genuine no-prompt transport gate:

```sh
make qualify-claude-transport \
  DAIMON_CLAUDE_PROGRAM=/absolute/path/to/claude
```

On this host `/opt/homebrew/bin/claude` version `2.1.311` completed the exact
initialize control handshake and bounded graceful local close. The gate sent no
`user` frame, so it is evidence for process/control compatibility only—not model
quality, prompt completion, tools, permissions or provider recovery.

The live-model gate is implemented but remains explicitly opt-in because it
spends one provider turn:

```sh
make qualify-claude-live \
  DAIMON_CLAUDE_ENABLE_PROMPT=1 \
  DAIMON_CLAUDE_PROGRAM=/absolute/path/to/claude
```

It submits one bounded no-tool prompt, makes no permission decision, requires
nonempty assistant output plus a matching completed terminal event, and closes
the child. A passing source-level gate is not claimed until that command has
actually completed against the selected installed provider. The 2026-11-16 run
did not: the provider returned nonempty assistant output followed by the
error-marked success subtype above. Anthropic's Agent SDK error contract treats
that shape as a terminal API failure, so `is_error` remains authoritative and
the gate fails closed. The polling fuel now covers the full declared 120-second
session bound and the disposable workspace is removed on both pass and panic;
neither change relaxes the required completed terminal event.
The later explicit-`sonnet` run stayed active through that full bound and
returned no terminal result. It likewise remains a failed qualification: a
model alias, assistant text, or elapsed polling fuel cannot substitute for the
provider's terminal envelope.
Hermetic process qualification now additionally proves that provider exit after
prompt dispatch becomes outcome-unknown and an `Advance` cannot relaunch it.
Stale permission request and option identities are refused without consuming
the exact retained valid challenge. The child environment is cleared before an
exact name allowlist is copied, and launch diagnostics expose neither arguments
nor environment names. A result arriving before the required correlated
interrupt acknowledgement makes cancellation outcome-unknown rather than
claiming success from an ambiguous race.
The adapter also negotiates through the shared digest-bound macOS Seatbelt
launcher under a deny-default fixture policy. The mechanism gate independently
proves file mutation is denied; it does not certify a deployment's policy.

Permission/tool journeys need a separately authorized disposable workspace and
must not infer approval from provider text. Production claims additionally need
a reviewed provider-specific policy or non-macOS sandbox backend, live
crash/restart reconciliation, version pinning and a live mixed-provider prompt
ensemble. The credential-free mixed-transport fixture gate is
`make qualify-agent-router`. Its opt-in live peer passed on 2026-11-16 against
installed `codex-acp` 1.8.0 and Claude Code 2.1.311, opening and closing both
real sessions concurrently through one profile-selected provider-neutral router
without submitting a model prompt.

Primary protocol references:

- [Claude Code CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-usage)
- [Official Python Agent SDK client](https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/client.py)
- [Official Python Agent SDK control channel](https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/_internal/query.py)
- [Official Python Agent SDK terminal error contract](https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/_errors.py)
