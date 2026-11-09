# Domain model

An execution is an attempt to perform one authorized request. It is not a Chronos
task and cannot change task state directly. A runtime adapter translates attributed
execution evidence back through Moira to the owning Chronos attempt.

The request contains only bounded values and references: execution and attempt IDs,
agent principal, harness profile, context references, allowed tool capabilities,
budgets, and an idempotency key. Context references do not grant read authority.

The result is a closed disposition plus bounded output proposals and evidence.
Agora messages and Vellum edits are proposals until their owning engine accepts
them. Daimon does not report those external effects as complete.

