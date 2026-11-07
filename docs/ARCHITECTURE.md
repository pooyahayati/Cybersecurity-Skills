# Architecture and accepted decisions

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
