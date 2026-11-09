# Daimon

Daimon is the provider-neutral agent harness protocol and execution runtime.
It executes already-authorized work under explicit budgets and returns attributed
evidence. It does not decide which work exists, schedule retries, define room
behavior, or own document publication.

Moira requests execution, Chronos owns the task lease, Aegis supplies authority,
optional Dendrite calls supply authored grounding, and Vellum handles document
edits. Model and tool providers remain adapters.

The first deterministic fake-harness slice now implements bounded preparation,
authority/tool validation, exact Chronos-attempt correlation, matching replay,
idempotency conflicts, provider-receipt attribution, and terminal result replay.
It invokes no provider, sandbox, model, tool, process, or network service. See
[requirements](requirements.md), [specification](specification.md), and the
[roadmap](docs/roadmap.md).

## Development

```sh
make check
```

