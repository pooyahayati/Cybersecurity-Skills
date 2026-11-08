# Implementation roadmap

The agreed product is a standalone, modular security skill for novice developers.
This roadmap defines implementation order and exit conditions. It does not grant
permission to scan a target, publish a release, or deploy changes.

## M0 — Development foundation

**Scope:** independent entrypoint; English architecture and domain guidance;
module/source catalogs; freshness, authorization and evidence contracts; report
templates; repository validator; regression checks; GitHub integration.

**Exit:** documented commands work; catalog/reference errors fail clearly;
foundation limits are explicit; private artifacts are excluded; reviewed changes
are integrated and CI results are observed. No operational assessment claim.

## M1 — Freshness and controlled execution

**Depends on:** M0.

Implemented scope and operator contracts are in
[M1 control-plane design](docs/M1-CONTROL-PLANE.md) and
[M1 operations](docs/M1-OPERATIONS.md). See `STATUS.md` for verified delivery state.
The first backend is offline local Linux Docker, with public GitHub acquisition;
network-enabled and other execution backends require separate future work.

- Resolve current stable releases from explicit official sources. Use the latest
  authoritative default-branch commit only when a project has no stable release.
- Verify actual installed/executed identity, artifact integrity and available
  provenance. Review instruction, dependency, permission and license changes.
- Quarantine candidates; validate compatibility; activate atomically. Reload an
  updated head and repeat preflight. Never execute candidate install hooks first.
- Keep a bounded run's verified components immutable; refresh on a new run,
  material resume or newly activated module. Revocation interrupts affected work.
- Bind host-enforced scope, permissions, egress, budget, timeout and cancellation
  to execution. Declare explicitly where the host cannot enforce a boundary.
- Store version and execution receipts outside target repositories. Separate
  observations from trusted execution evidence; do not trust self-written flags.

**Exit:** realistic fixtures reject stale binaries, stale feeds, false version
claims, redirected sources, identity changes, incompatible updates, unavailable
upstream metadata, permission escalation and interrupted activation. No old
version may silently satisfy the current-version requirement. Unaffected planning
can continue with a precise blocked-module explanation.

## M2 — Discovery, coverage and evidence

**Depends on:** M1 for operational execution.

Implemented design and operator contracts are in
[M2 discovery and evidence](docs/M2-DISCOVERY-EVIDENCE.md) and
[M2 operations](docs/M2-OPERATIONS.md). Current verified results are in `STATUS.md`.

- Discover source-only, URL-only and combined target capabilities; retain unknowns.
- Map actors, assets, data flows, stack versions and environment identities.
- Route modules from corroborated facts. Inventory applicable controls with
  versioned standard identifiers and explicit coverage states.
- Implement finding records, counterevidence, root-cause deduplication, attack-chain
  links, redaction, evidence invalidation and novice-first reports.

**Exit:** limited access cannot yield a full pass; source and deployed revisions
cannot be conflated; missing evidence is visible; synthetic customer data and
secrets are not exposed in logs or reports. Validate schemas and their semantics.

## M3 — Source, identity, data and remediation

**Depends on:** M2.

The bounded implementation is documented in
[M3 source/remediation contracts](docs/M3-SOURCE-REMEDIATION.md) and
[M3 operations](docs/M3-OPERATIONS.md). `STATUS.md` records observed verification.
Finite syntax leads and serialized-model retests do not establish universal
vulnerability coverage, real database state or deployed remediation.

- Implement source/architecture, identity/session, data-lifecycle, business-logic
  and dependency/secret assessment paths with selected specialist adapters.
- Prioritize JavaScript/TypeScript, Python and PHP support; add WordPress and
  WooCommerce only on platform evidence and match the actual installed version.
- Separate source inspection from builds and test execution of untrusted projects.
- Implement scoped patch proposals, legitimate/denied-flow checks, protected-state
  assertions, related-variant checks and post-patch verification.

**Exit:** vulnerable and safe near-match fixtures distinguish real issues from
false positives; known protected-data and cross-owner scenarios are covered;
incomplete patches fail retesting; legitimate workflows continue to work. Record
measured results, not universal detection or protection guarantees.

## M4 — Runtime, infrastructure and delivery

**Depends on:** M2; consume M3 findings for source-to-runtime correlation.

- Implement scoped deployed web/API checks and authenticated role comparisons.
- Add reviewed tool adapters for Trivy, source analysis and dynamic testing;
  select tools by capability and license, not by mandatory tool count.
- Cover host/cloud access, storage exposure, containers, IaC and CI/CD boundaries.
- Verify artifact-to-environment identity, pre-release controls and bounded
  post-release checks. Preserve legitimate redirects without escaping scope.

**Exit:** fixtures catch cross-target redirects, unsafe active scan selection,
deployed-version mismatch, infrastructure exposure and build/deploy secret leaks.
URL-only assessments report inaccessible source/infrastructure as unverified.

## M5 — Capacity, concurrency, recovery and incidents

**Depends on:** M4.

- Implement measured workloads, concurrency/RPS distinctions, latency percentiles,
  errors, saturation and persisted-state correctness. Add a reviewed k6 adapter.
- Cover baseline/load/stress/spike/soak/breakpoint scenarios only where justified.
- Bind production rate/duration/concurrency budgets and abort thresholds; use
  staging for heavy and fault-inducing tests unless separately authorized.
- Verify backup restoration, rollback, alerts and recovery objectives with
  representative disposable data. Add evidence-preserving incident triage.

**Exit:** tests stop at their bounds; overload cannot be called capacity success;
duplicate transactions and state corruption are detected; an existing but
unrestorable backup fails recovery acceptance. No implied recurring monitoring.

## M6 — Behavioral qualification and stable packaging

**Depends on:** all required operational milestones for the claimed release scope.

- Run the evaluation protocol in `docs/EVALUATION.md` with a documented baseline.
- Evaluate supported platforms and degraded modes; address missed important
  findings, false alarms, unsafe actions and incorrect remediation.
- Test installation/update/uninstall without modifying unrelated skills or data.
- Publish only supported capabilities, current limitations, provenance and actual
  evaluation results. Verify the exact packaged artifact before stable release.

**Exit:** agreed risk-relevant scenarios pass; unresolved critical control failures
block release. The skill has measured support boundaries and usable novice
reports. A passing repository validator alone cannot satisfy this milestone.

## Maintenance after a stable release

Recheck upstream changes, license constraints, advisories, tool/rule data and
behavior regressions. Open maintenance work from observed changes. Scheduled
assessment or production monitoring requires a separate explicit configuration;
creating this project does not schedule either.
