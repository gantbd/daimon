# Roadmap

## Phase 0 — protocol closure

- Close request, budgets, context references, tool capabilities, outcomes, and
  evidence vocabularies.
- Threat-model prompt injection, confused deputy, tool escalation, secret leakage,
  replay, cancellation races, and resource exhaustion.
- Define the fake-provider contract used by Moira's first vertical slice.

## Phase 1 — deterministic fake harness

- [In progress] Prepare/dispatch, authority/tool/budget validation, idempotent
  matching replay, conflicting replay, and bounded result evidence are implemented.
- Add cancellation, timeout, saturation, and shutdown scenarios.
- Produce bounded Agora-message and Vellum-edit proposals without publishing them.

## Phase 2 — connector protocol

- Define provider and tool ports plus attributed receipts.
- Qualify one local fake process adapter with fault injection.
- Add unknown-effect reconciliation before any live model connector.

## Phase 3 — selected provider

- Select and document one model profile and one tool profile.
- Add live conformance tests separately from deterministic core evidence.
- Integrate Dendrite only as an optional bounded grounding provider.

