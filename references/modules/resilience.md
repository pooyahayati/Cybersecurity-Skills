# Capacity, availability, recovery and incident triage

Define representative workflows, dataset, cache state, think time, resources,
external-service behavior and acceptance criteria. Distinguish virtual users,
in-flight requests and requests per second. Check load-generator limitations.

Choose smoke, normal load, stress, spike, soak or breakpoint tests from the actual
question. Record throughput, latency percentiles, errors and resource saturation
alongside persisted-state correctness. Do not extrapolate unlimited capacity from
one short test or count rejected requests as successful business throughput.

Use staging for heavy or fault-inducing tests by default. Production requires
explicitly scoped rate/concurrency/duration/cost limits, enforced abort thresholds,
an operator stop path and recovery readiness. A retry must consume the same budget.

Verify backups by restoring representative disposable data and checking integrity.
Test relevant rollback, alert delivery and recovery objectives; file existence and
process health are insufficient. Preserve evidence when compromise is suspected;
separate immediate authorized containment from destructive cleanup and recovery.

Report security, capacity, data integrity and recovery outcomes separately. The bounded M5 paths are implemented in [M5 operations](../../docs/M5-OPERATIONS.md)
and [M5 contracts](../../docs/M5-RESILIENCE.md). A catalog entry does not activate
or authorize k6. Preserve the distinction between sampled read performance,
artifact integrity, disposable restore and service recovery.
