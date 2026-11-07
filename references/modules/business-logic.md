# Business logic and concurrent integrity

Identify business invariants before testing: ownership, pricing, entitlements,
balance, inventory, reservation uniqueness, payment state and allowed transitions.
Ask only for consequential business rules that cannot be inferred reliably.

Examine skipped/reordered steps, parameter tampering, replay, duplicate callbacks,
partial failure, retry, concurrent requests and cross-channel inconsistencies.
Verify transaction boundaries, idempotency scope and durable state; a success
message or a rejected request does not prove financial/data integrity.

Use synthetic data and sandbox providers. Do not make real payments, send real
messages or consume customer inventory without specific authorization. Bound
concurrency and request counts and inspect persisted results after the test.

Return the violated invariant, actor, safe reproduction and affected state. Fix the
server-side invariant rather than adding a browser-only guard. Retest duplicate and
legitimate operations and inspect any remaining retry/reconciliation behavior.
