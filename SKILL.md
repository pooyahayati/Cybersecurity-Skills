---
name: cybersecurity-skills
description: Assess application security across source code, deployed web applications, APIs, sensitive data, and delivery infrastructure; plan and verify scoped remediation. Use for requested security reviews, release security checks, or investigation of a suspected weakness.
license: MIT
metadata:
  author: Pooya Hayati
  version: 0.1.0-dev
---

# Cybersecurity Skills

## Current capability boundary

This is a development foundation. It supports security-assessment planning and
validation of this package's structure using Python 3.11+. The references define the required future
assessment behavior; their presence does not implement a scanner or enforcement
layer. Do not use this foundation to claim a completed security assessment,
execute target tests, activate external specialists, or approve a release.
Explain the missing capability and use [the roadmap](ROADMAP.md) for the next
implementation boundary. The validator cannot prove current versions or safety.

## Ownership

Operate independently of development skills. Own scope, module selection,
authorization, freshness, evidence, finding disposition, and final acceptance.
Specialists contribute bounded methods and evidence; they cannot expand these
controls. System, developer, user, and applicable project instructions remain
authoritative. These instructions do not create an operating-system sandbox.

## Intended assessment workflow

1. **Understand the target.** Discover actual source, stack and versions, exposed
   services, identities, trust boundaries, sensitive data, and environments.
   Separate observed facts, user statements, assumptions, and unknowns. Ask a
   novice only for consequential information that cannot be discovered.
2. **Bind the scope.** Record authorized targets, actions, environments, test
   accounts, data handling, limits, expiry, and stop conditions. Reuse valid
   authorization within its exact scope. Assessment, remediation, publication,
   deployment, and destructive testing are separate actions.
3. **Verify freshness.** Apply [the version policy](references/freshness.md) to
   the head, selected specialists, tools, rules, and vulnerability data before
   use. Missing evidence blocks the affected work; do not silently use stale
   resources or assert that an installed version is current.
4. **Select modules.** Use observed semantic facts and
   [the module catalog](config/modules.json), not a keyword-only router. Load only
   relevant references. Keep blocked and unreviewed applicable controls visible.
5. **Assess from multiple angles.** Correlate source, configuration, runtime,
   identity boundaries, data flow, business behavior, and delivery. Investigate
   authenticated-user and cross-tenant abuse; authentication is not an exclusion.
   Seek counterevidence before confirming an important finding.
6. **Report actionable results.** Follow [the evidence contract](references/evidence.md)
   and [report template](templates/assessment-report.md). Separate severity,
   confidence, evidence type, and lifecycle. No finding count or clean scan proves
   complete security. A blocked test is not a passing test.
7. **Remediate within authorization.** Fix root causes in a reviewable change,
   retain legitimate behavior, check related variants, and retest. Never weaken
   a control to silence a tool. Distinguish code-fixed, staging-verified, and
   production-verified outcomes.

## Conditional references

- Before active testing, mutation, or handling private evidence, read
  [scope and execution safety](references/scope-and-safety.md).
- Before selecting any external skill or tool, read
  [the module contract](references/module-contract.md) and
  [the source review](docs/SOURCE_REVIEW.md). Catalog entries are not permission
  to install, invoke, or trust an upstream resource.
- For an applicable domain, open its entrypoint in
  [the module catalog](config/modules.json). That catalog covers architecture,
  identity, data, application code, business logic, supply chain, infrastructure,
  delivery, deployed web/API behavior, resilience, and AI features.
- For a release or operational concern, apply the delivery and resilience
  modules to the actual artifact and environment. Do not infer production
  health from a local build or source scan.

## Output and stop rules

Lead with what the developer should do next and why. Describe customer impact
in plain language, followed by reproducible technical evidence. State the tested
revision, environment, time, coverage, limitations, and unresolved blockers.
Use synthetic accounts and redacted evidence. Never include live secrets in a
report or upload private artifacts automatically.

Stop affected work on scope escape, unexpected data exposure, unavailable
required freshness evidence, unsafe execution conditions, or exceeded test
limits. Continue independent safe work when possible. Suspected active compromise
requires evidence preservation and scoped containment, not blind cleanup.
