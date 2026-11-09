# Architecture and accepted decisions

M5 adds `ResilienceReview`, a separate current-version `LoadController` and a
trusted exact-route broker. Native k6 receives generated loopback tickets only;
M1 stays offline and parses/restores selected SQLite artifacts. The private ledger
binds recovery challenges, observed receiver acknowledgments and incident custody.
See [M5 contracts](M5-RESILIENCE.md); no module implies whole-system approval.

M4 extends `SourceReview` through a distinct `RuntimeReview` engine. A trusted
single-request HTTP worker has separate exact network authority and producer
records; it never grants network access to M1's untrusted execution. Configuration
workers remain offline in M1. Read-only local Docker observations and deployed
reads have different provenance and do not establish URL-to-container routing.
See [M4 contracts](M4-RUNTIME-SECURITY.md) for trust, scope and supported claims.

M3 extends the M2 ledger through `SourceReview`, reusing M1 operation provenance
and private immutable snapshots. Static leads, attributed source traces and finite
serialized-model remediation have separate acceptance semantics; none establishes
deployed security. See [M3 contracts](M3-SOURCE-REMEDIATION.md) for exact boundaries.

## Product contract

A novice developer should be able to request a security review without selecting
tools or knowing vulnerability names. The eventual skill discovers available
evidence, selects applicable checks, explains risk, proposes bounded remediation
and verifies outcomes. It must remain useful with source-only, URL-only or combined
access without pretending that unavailable surfaces were assessed.

## Components

| Component | Owns | Does not own |
|---|---|---|
| Head skill | Scope, coverage, freshness, evidence, prioritization, acceptance | Host permissions or operating-system isolation |
| Domain module | Scoped methods, findings, counterevidence, verification requirements | Global workflow, expanded access, release approval |
| Platform adapter | Version-appropriate behavior for an observed platform | A mandatory platform or automatic application upgrade |
| Tool adapter | Bounded execution, version/data identity, normalized observations | Truth of a finding or permission to test |
| Execution controller, M1 | Reviewed activation, offline Docker scope/limits, cancellation and authenticated records | Product decisions or permission inferred from target text |
| Runtime collector, M4 | Exact authorized reads, TLS/address/redirect bounds, durable budgets and typed evidence | Crawling, active payloads, target mutation or image routing attestation |

`SKILL.md` is the compact entrypoint. `config/modules.json` catalogs original
domain guidance; `config/sources.json` lists disabled external candidates.
References are loaded selectively. Tools supplement semantic and business-logic
review. There is no mandatory outside head skill and no wholesale plugin import.

## Decisions

1. **Independent runtime.** Vibe is a development method only. The runtime catalog
   must not depend on Vibe or the excluded Persian-writing skill.
2. **Stdlib controller.** Python 3.11+ and SQLite from its standard library provide
   parsing, authenticated atomic state and controller logic. M1 uses an existing
   local Linux Docker engine for enforced execution; no Python dependency manager
   or always-running controller service is required.
3. **Policy versus enforcement.** Written requirements are not an enforcement
   engine. M1 implements the bounded controls described in
   [its design](M1-CONTROL-PLANE.md); an application auditor remains later work.
4. **Current but reproducible.** Resolve the current official stable candidate,
   verify it, then freeze exact identities for one bounded run. Never silently
   fall back to stale components. An unavailable optional module does not stop
   independent safe work, but its coverage remains blocked.
5. **Evidence before labels.** Severity, confidence, evidence level, coverage and
   remediation status are independent dimensions. A formatting or scanner pass
   does not establish an application-security outcome.
6. **Risk-sensitive operations.** Authorization binds targets, actions, accounts,
   environments and limits. Reuse an existing valid scope; ask only for genuinely
   missing or changed consequential authorization.
7. **No private state in source.** Runtime receipts, target mappings, raw findings
   and scanner output stay outside both this package and the target repository.
   A deliberately sanitized report may be delivered to an authorized location.
8. **Version-matched platforms.** PHP, WordPress/WooCommerce and other platform
   packs activate from observed evidence and use the target's actual versions.
   Updating the auditor is not authorization to upgrade the application.

## Intended execution flow

M6 adds exact-source packaging and bounded qualification around these assessment
paths. The package builder reads selected Git blobs, records their identities and
emits a deterministic archive. A separate explicit-root lifecycle manager uses
private ownership records, a process lock and resumable directory transactions.
Neither archive inspection nor installation executes candidate code, establishes
freshness, changes M1-M5 authority or qualifies a customer application. See
[M6 contracts and operations](M6-QUALIFICATION.md).

Scope and discovery -> freshness and compatibility -> module plan -> bounded
assessment -> refutation and validation -> actionable report -> authorized fix ->
retest -> environment-specific disposition.

Discovery is iterative: new evidence can activate another module, but that module
must complete its own preflight before use. Missing access remains an explicit
coverage gap. A critical advisory or revoked component invalidates affected work.

## Foundation impact analysis

The initial change affects instructions, catalogs, documentation, a read-only
validator and development CI. It does not inspect a customer's application, fetch
upstream skills, execute target code or enforce runtime authorization. The main
risks are misleading readiness claims, accidental candidate activation, unsafe
file references and incomplete future control definitions. Foundation tests cover
the implemented metadata/path behavior; domain accuracy needs later evaluations.
