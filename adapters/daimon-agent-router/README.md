# Daimon agent router

`daimon-agent-router` composes multiple interactive-agent transports behind
Daimon's single provider-neutral `AgentProvider` port. Administrator-owned
configuration assigns each frozen profile document digest to exactly one
backend. The router records that backend before the first open dispatch and
keeps the association for the bounded lifetime of the router, including an
ambiguous provider outcome.

Public requests cannot choose a backend independently of the profile already
resolved by Daimon. Prompt routing additionally checks that the retained
session route and supplied frozen profile agree. Unknown sessions, duplicate
opens, profile drift, capacity exhaustion, and unregistered profiles produce
`OutcomeUnknown` without probing another backend.

The process qualification runs real hermetic ACP and Claude stream-JSON
fixtures concurrently through one router:

```text
cargo test -p daimon-agent-router --test mixed_provider_process --locked --offline
```
