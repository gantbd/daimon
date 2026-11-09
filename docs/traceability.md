# Traceability ledger

| Requirement | Planned implementation | Current evidence | Status |
| --- | --- | --- | --- |
| D1 external work | request-only protocol | boundary document | Open |
| D2 identity | fixed-width IDs and authority-free exact task-attempt reference | preparation/provider receipt scenarios | Partial; production adapter mapping open |
| D3 budgets | `ExecutionBudgetV1`, profile ceilings, pre-publication validation | zero/ceiling and output checks in deterministic core | Partial; elapsed/provider enforcement open |
| D4 tools | authority evidence finite tool set and request subset check | unauthorized tool and expired authority BDD | Partial; Aegis adapter open |
| D5 outcomes | closed disposition and attributed provider receipt | completion/replay scenarios | Partial; cancellation/timeout/uncertainty expansion open |
| D6 idempotency | retained request/result maps keyed by fixed idempotency/execution IDs | matching prepare/result replay and conflict BDD | Satisfied for volatile fake harness |
| D7 provenance | bounded result evidence | type skeleton | Open |
| D8 isolation | dependency-free deterministic fake core | current crate graph and strict lint | Satisfied for current core |
| D9 shutdown | retained execution ownership | none | Open |

