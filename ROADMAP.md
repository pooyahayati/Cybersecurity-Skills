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

The bounded implementation is documented in [M4 contracts](docs/M4-RUNTIME-SECURITY.md)
and [M4 operations](docs/M4-OPERATIONS.md). Its dynamic adapter performs exact
authorized reads; the selected Trivy scope is release-embedded secret/configuration
rules. Host/cloud coverage uses selected configuration evidence and local container
observations. General active scanning and remote administrative collectors are
unsupported. Artifact correspondence does not establish build provenance, URL
routing or deployment approval. `STATUS.md` records actual verification.

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

The bounded implementation is documented in [M5 contracts](docs/M5-RESILIENCE.md)
and [M5 operations](docs/M5-OPERATIONS.md). Read workloads and SQLite artifact
checks are distinct. Target resource saturation, deployed state linkage and
whole-service recovery remain unverified; no broad qualification is implied.

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

The bounded qualification and candidate-package contract is in
[M6 qualification and packaging](docs/M6-QUALIFICATION.md). Measured results and
unverified surfaces belong in `STATUS.md`; a prepared candidate is not a stable
release or a general-purpose application-security qualification.

- Run the evaluation protocol in `docs/EVALUATION.md` with a documented baseline.
- Evaluate supported platforms and degraded modes; address missed important
  findings, false alarms, unsafe actions and incorrect remediation.
- Test installation/update/uninstall without modifying unrelated skills or data.
- Publish only supported capabilities, current limitations, provenance and actual
  evaluation results. Verify the exact packaged artifact before stable release.

**Exit:** agreed risk-relevant scenarios pass; unresolved critical control failures
block release. The skill has measured support boundaries and usable novice
reports. A passing repository validator alone cannot satisfy this milestone.

## Release-readiness follow-up baseline

The follow-up delivered the bounded `1.0.0-rc.1` candidate without stable publication.
Support canonical version channels, retain M1-M5 state and authority contracts,
add offline managed-install diagnosis, execute actual M1-M5 workflows from the
installed artifact, and observe real host catalog discovery in an isolated
project. Document supported scope and explicit upgrade/rollback. Require
independent review, native source/artifact scans and exact-revision hosted checks.
See [the release contract](docs/RELEASE-READINESS.md) and actual [status](STATUS.md).

## Checklist completion workstream

The [C1-C6 roadmap](docs/CHECKLIST-ROADMAP.md) addresses the gaps identified by
comparing the 36 Security Audit items in the service checklist with implemented
behavior. C1 implements complete coverage planning and validation. C2-C6 add
separate bounded dependency/advisory, web, target-scenario, infrastructure and
recovery profiles described in [the execution guide](docs/CHECKLIST-EXECUTION.md).
Their original exit criteria remain binding; [status](STATUS.md) separates actual
qualification, observed failures and subsequent delivery. Profile availability does not close all
target checklist items or authorize every candidate tool.

## Stable-release completion work

M1-M6 and the selected C1-C6 profiles are implemented; this is not a claim that
all target controls or platforms are qualified. The current candidate also fixes
the observed post-merge SQLite contention error, with all five checks successful
before and after the PR11 merge. Version `1.0.0` preparation now addresses the
remaining qualification and exact-asset gates in the ordered
[stable-release checklist](docs/RELEASE-READINESS.md#stable-release-checklist):

1. Resolve required failures and observe passing exact-revision platform and
   installed-workflow checks; retain the original failures and independent review.
2. Freeze the bounded release claim and perform relevant current-candidate
   novice/agent exercises with independent expectations and explicit limitations.
3. Prepare the exact stable-labelled source/archive, then verify affected
   installation, upgrade/restoration and actual host registration behavior.
4. Refresh selected prerequisite identities, scan final source/extracted bytes,
   reconcile independent acceptance and verify archive/digest/source correspondence.
5. Obtain explicit stable-publication authority for the concrete reviewed result,
   publish it and verify the downloaded public asset and release metadata.

Run only checks justified by changed inputs and release claims. Preserve previous
evidence where it remains applicable; no universal test quota or compulsory
installation of disabled candidates is introduced. Browser/JavaScript, additional
ecosystems/databases, remote clouds and external detection systems are later
capability work unless included in the selected release claim. Global installation
and customer execution remain separately authorized actions.

## Maintenance after a stable release

Recheck upstream changes, license constraints, advisories, tool/rule data and
behavior regressions. Open maintenance work from observed changes. Scheduled
assessment or production monitoring requires a separate explicit configuration;
creating this project does not schedule either.
