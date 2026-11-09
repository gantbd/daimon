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

